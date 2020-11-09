import argparse
import concurrent.futures
import datetime
import functools
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, cast

import jinja2
import requests
import stackprinter
import tenacity
import yaml

import logfiles


root = pathlib.Path(__file__).parent.parent
config_yml = root / "config.yml"
watch_overrides_dir = root / "watch_overrides"
# Using docs/ for generated dir -- awkward, but that's the only
# directory supported by GitHub Pages.
generated_dir = root / "docs"
generated_dir.mkdir(exist_ok=True)
used_config_yml = generated_dir / "used_config.yml"
registry_yml = generated_dir / "registry.yml"
feeds_txt = generated_dir / "feeds.txt"
logfile = logfiles.generate_logfile_path()

persisted_dir = root / "cache"
persisted_dir.mkdir(exist_ok=True)
persisted_data_yml = persisted_dir / "persisted_data.yml"

session = requests.Session()
session.request = functools.partial(session.request, timeout=5)  # type: ignore


def init_logger() -> logging.Logger:
    logger = logging.getLogger(__file__)
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    sh.setLevel(logging.INFO)
    fh = logging.FileHandler(logfile)
    fh.setFormatter(formatter)
    fh.setLevel(logging.INFO)
    logger.addHandler(sh)
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)
    return logger


logger = init_logger()
stackprinter.set_excepthook()


class SafeLoadableYAMLObject(yaml.YAMLObject):
    yaml_loader = yaml.SafeLoader


@dataclass
class FeedConfig(SafeLoadableYAMLObject):
    yaml_tag = "!FeedConfig"
    base_url: str
    author: str = "release-feeds"
    aggregate_title: str = "Aggregate software releases"


@dataclass
class Config(SafeLoadableYAMLObject):
    yaml_tag = "!Config"
    feed: FeedConfig
    packages: List[str]


@dataclass
class PackageVersion(SafeLoadableYAMLObject):
    yaml_tag = "!PackageVersion"
    version: str
    archive_url: str


@dataclass
class FeedEntry(SafeLoadableYAMLObject):
    yaml_tag = "!FeedEntry"
    id: str
    package_name: str
    package_version: PackageVersion
    updated: datetime.datetime


@dataclass
class Feed(SafeLoadableYAMLObject):
    yaml_tag = "!Feed"
    uri: str
    title: str
    author: str
    updated: datetime.datetime
    entries: List[FeedEntry]


# The Registry type maps package names to corresponding feed entries.
Registry = Dict[str, FeedEntry]


@dataclass
class Persisted(SafeLoadableYAMLObject):
    yaml_tag = "!Persisted"
    last_successful_crawls: Dict[str, datetime.datetime] = field(default_factory=dict)

    # A custom serializer so that timestamps aren't shown in repr form.
    def __str__(self):
        last_successful_crawls = {
            package: str(timestamp)
            for package, timestamp in self.last_successful_crawls.items()
        }
        return f"Persisted(last_successful_crawls={last_successful_crawls})"


# Global singleton.
persisted_data = Persisted()


class RetriableException(Exception):
    pass


# uscan could fail for retriable reasons, most obviously temporary
# network problems.
class UscanFailed(RetriableException):
    pass


class IgnorableException(RetriableException):
    pass


# Debian's shitty sources.debian.org API routinely fails to return the
# sid version, so we need to make a special exception for this exception
# to reduce false positive alerts.
class NoSidVersionFound(IgnorableException):
    pass


# Time we can tolerate an IgnorableException to repeat before finally
# failing an update and alerting the human overseer.
IGNORE_THRESHOLD = datetime.timedelta(hours=1)


def iso8601_format(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso8601_parse(s: str) -> datetime.datetime:
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z")


jinja_env = jinja2.Environment(autoescape=True, keep_trailing_newline=True)
jinja_env.filters.update(
    # force_tostring forces markupsafe.Markup to be further escaped.
    # This is needed for atom:content where html content has to be
    # escaped.
    force_tostring=str,
    iso8601_format=iso8601_format,
)


feed_template = jinja_env.from_string(
    """\
{%- macro content(url) -%}
<p><a href="{{ url }}" target="_blank" rel="noopener noreferrer">{{ url }}</a></p>
{%- endmacro -%}

<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>{{ feed.uri }}</id>
  <title>{{ feed.title }}</title>
  <author>
    <name>{{ feed.author }}</name>
  </author>
  <updated>{{ feed.updated|iso8601_format }}</updated>
  <link rel="self" href="{{ feed.uri }}"/>
  {%- for entry in feed.entries %}
  <entry>
    <id>{{ entry.id }}</id>
    <title>{{ entry.package_name }} {{ entry.package_version.version }}</title>
    <author>
      <name>{{ entry.package_name }} authors</name>
    </author>
    <link rel="enclosure" type="application/octet-stream" href="{{ entry.package_version.archive_url }}"/>
    <content type="html">{{ content(entry.package_version.archive_url)|force_tostring }}</content>
    <updated>{{ entry.updated|iso8601_format }}</updated>
  </entry>
  {%- endfor %}
</feed>
"""
)


def write_changelog(package: str, destdir: pathlib.Path) -> None:
    with destdir.joinpath("changelog").open("w", encoding="utf-8") as fp:
        fp.write(
            f"""\
{package} (0.0.0-1) unstable; urgency=medium

  * XXX

 -- John Doe <jd@example.com>  Thu, 01 Jan 1970 00:00:00 +0000
"""
        )


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(RetriableException),
    wait=tenacity.wait_exponential(multiplier=2, max=15),
    stop=tenacity.stop_after_attempt(3),
    after=lambda retry_state: logger.warning(
        f"retrying download_watch_file for {retry_state.args[0]} "
        f"(attempt #{retry_state.attempt_number})"
    ),
)
def download_watch_file(package: str, destdir: pathlib.Path) -> None:
    # Get latest version of package in debian sid.
    url = f"https://sources.debian.org/api/src/{package}/"
    logger.info(f"GET {url}")
    r = session.get(url)
    assert r.status_code == 200
    payload = r.json()
    if "error" in payload:
        raise RuntimeError(f"GET {url}: {r.text}")
    for version_info in payload["versions"]:
        if "sid" in version_info["suites"]:
            version: str = version_info["version"]
            break
    else:
        raise NoSidVersionFound(f"no sid version found for {package}: {r.text}")

    # Get URL of debian/watch in the latest version.
    url = f"https://sources.debian.org/api/src/{package}/{version}/debian/watch"
    logger.info(f"GET {url}")
    r = session.get(url)
    assert r.status_code == 200
    payload = r.json()
    if "error" in payload:
        raise RuntimeError(f"GET {url}: {r.text}")
    try:
        raw_url = urllib.parse.urljoin(url, payload["raw_url"])
    except KeyError:
        raise RuntimeError(f"no raw_url for {package}/{version}/debian/watch: {r.text}")

    # Download debian/watch.
    logger.info(f"GET {raw_url}")
    r = session.get(raw_url)
    assert r.status_code == 200
    with destdir.joinpath("watch").open("w", encoding="utf-8") as fp:
        fp.write(r.text)


def acquire_watch_file(package: str, destdir: pathlib.Path) -> None:
    override_path = watch_overrides_dir / package
    if override_path.exists():
        shutil.copyfile(override_path, destdir / "watch")
    else:
        download_watch_file(package, destdir)


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(RetriableException),
    wait=tenacity.wait_exponential(multiplier=2, max=15),
    stop=tenacity.stop_after_attempt(3),
    after=lambda retry_state: logger.warning(
        f"retrying uscan for {retry_state.args[0]} "
        f"(attempt #{retry_state.attempt_number})"
    ),
)
def uscan(package: str, source_dir: pathlib.Path) -> PackageVersion:
    try:
        report = subprocess.check_output(
            ["uscan", "--safe", "--dehs"], cwd=source_dir, encoding="utf-8",
        )
    except subprocess.CalledProcessError:
        raise UscanFailed(f"uscan for {package} failed")
    try:
        tree = ET.fromstring(report)
        version = cast(str, cast(ET.Element, tree.find("./upstream-version")).text)
        archive_url = cast(str, cast(ET.Element, tree.find("./upstream-url")).text)
    except ET.ParseError:
        raise RuntimeError(f"malformed report for {package}: {report}")
    return PackageVersion(version, archive_url)


def get_package_version(package: str) -> PackageVersion:
    with tempfile.TemporaryDirectory() as tmpdir:
        source_dir = pathlib.Path(tmpdir)
        debian_dir = source_dir / "debian"
        debian_dir.mkdir()
        write_changelog(package, debian_dir)
        acquire_watch_file(package, debian_dir)
        version = uscan(package, source_dir)
        logger.info(f"{package} {version.version}: {version.archive_url}")
        return version


def try_updating_entry(
    package: str, *, existing_entry: Optional[FeedEntry] = None
) -> Optional[FeedEntry]:
    latest_version = get_package_version(package)
    if existing_entry and latest_version == existing_entry.package_version:
        return None
    return FeedEntry(
        id=f"urn:uuid:{uuid.uuid1()}",
        package_name=package,
        package_version=latest_version,
        updated=datetime.datetime.now(datetime.timezone.utc),
    )


# Returns the updated registry, the list of updated packages, the list
# of failed packages, and the list of removed packages (previously in
# the registry, now delisted from config).
def update_registry(
    packages: List[str], *, jobs: int = 1
) -> Tuple[Registry, List[str], List[str], List[str]]:
    registry: Registry = dict()
    if registry_yml.exists():
        with registry_yml.open(encoding="utf-8") as fp:
            registry = yaml.safe_load(fp.read())

    removed_packages = [package for package in registry if package not in packages]
    for package in removed_packages:
        registry.pop(package)
        persisted_data.last_successful_crawls.pop(package)

    updated_packages = []
    failed_packages = []
    lock = threading.Lock()

    def try_updating_registry_entry(package: str) -> None:
        with lock:
            existing_entry = registry.get(package)
        try:
            entry = try_updating_entry(package, existing_entry=existing_entry)
        except Exception as e:
            processed = False
            ignorable = False
            if isinstance(e, tenacity.RetryError):
                try:
                    e.reraise()
                except RetriableException as wrapped_exc:
                    last_successful_crawl = persisted_data.last_successful_crawls.get(
                        package
                    )
                    if (
                        isinstance(wrapped_exc, IgnorableException)
                        and last_successful_crawl is not None
                        and (
                            delta := datetime.datetime.now(datetime.timezone.utc)
                            - last_successful_crawl
                        )
                        < IGNORE_THRESHOLD
                    ):
                        approx_time_since_last_success_crawl = datetime.timedelta(
                            seconds=round(delta.total_seconds())
                        )
                        logger.warning(
                            f"failed to update entry for {package} "
                            f"({approx_time_since_last_success_crawl} since last successful crawl): "
                            f"{wrapped_exc}"
                        )
                        ignorable = True
                    else:
                        logger.error(
                            f"failed to update entry for {package}: {wrapped_exc}"
                        )
                    processed = True
                except:
                    pass
            if not processed:
                logger.error(f"failed to update entry for {package}", exc_info=True)
            if not ignorable:
                with lock:
                    failed_packages.append(package)
            return
        with lock:
            persisted_data.last_successful_crawls[package] = datetime.datetime.now(
                datetime.timezone.utc
            )
            if entry:
                registry[package] = entry
                updated_packages.append(package)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        executor.map(try_updating_registry_entry, packages)

    with registry_yml.open("w", encoding="utf-8") as fp:
        fp.write("# AUTO-GENERATED -- DO NOT MODIFY\n")
        fp.write(yaml.dump(registry))
    return registry, updated_packages, failed_packages, removed_packages


def render_feed(feed: Feed, path: pathlib.Path):
    atom = feed_template.render(feed=feed)
    with path.open("w", encoding="utf-8") as fp:
        fp.write(atom)


def generate_single_package_feed(
    package: str, entry: FeedEntry, config: Config
) -> None:
    dest = generated_dir / f"{package}.xml"
    render_feed(
        Feed(
            uri=urllib.parse.urljoin(config.feed.base_url, f"{package}.xml"),
            title=f"{package} releases",
            author=config.feed.author,
            updated=entry.updated,
            entries=[entry],
        ),
        dest,
    )
    logger.info(f"generated {dest}")


def generate_aggregate_feed(registry: Registry, config: Config) -> None:
    dest = generated_dir / "aggregate.xml"
    render_feed(
        Feed(
            uri=urllib.parse.urljoin(config.feed.base_url, "aggregate.xml"),
            title=config.feed.aggregate_title,
            author=config.feed.author,
            updated=datetime.datetime.now(datetime.timezone.utc),
            entries=sorted(
                registry.values(), key=lambda entry: entry.updated, reverse=True
            ),
        ),
        dest,
    )
    logger.info(f"generated {dest}")


def generate_feed_index(registry: Registry, config: Config) -> None:
    with feeds_txt.open("w", encoding="utf-8") as fp:
        print("# AUTO-GENERATED -- DO NOT MODIFY", file=fp)
        print(urllib.parse.urljoin(config.feed.base_url, "aggregate.xml"), file=fp)
        for package in registry:
            print(urllib.parse.urljoin(config.feed.base_url, f"{package}.xml"), file=fp)


def remove_outdated_feeds(removed_packages: List[str]) -> None:
    for package in removed_packages:
        path = generated_dir / f"{package}.xml"
        if path.exists():
            path.unlink()
            logger.info(f"removed {path}")


# Returns current config object, and prior config object if possible.
def load_config() -> Tuple[Config, Optional[Config]]:
    with config_yml.open(encoding="utf-8") as fp:
        config = yaml.safe_load(fp.read())
    if not isinstance(config, Config):
        raise RuntimeError(f"malformed config: expected config object, got {config}")
    logger.info(f"config: {config}")

    prior_config = None
    if used_config_yml.exists():
        try:
            with used_config_yml.open(encoding="utf-8") as fp:
                prior_config = yaml.safe_load(fp)
            assert isinstance(prior_config, Config)
            str(prior_config)  # this can shake out problems like missing attributes
        except Exception:
            logger.warning(
                f"failed to load prior config from {used_config_yml}", exc_info=True
            )

    return config, prior_config


def dump_config(config: Config) -> None:
    with used_config_yml.open("w", encoding="utf-8") as fp:
        fp.write("# AUTO-GENERATED -- DO NOT MODIFY\n")
        fp.write(yaml.dump(config))


def load_persisted_data() -> None:
    global persisted_data
    if not persisted_data_yml.exists():
        return
    with persisted_data_yml.open(encoding="utf-8") as fp:
        loaded = yaml.safe_load(fp.read())
    if not isinstance(loaded, Persisted):
        logger.warning(f"malformed persisted data: got {loaded}")
        return
    persisted_data = loaded
    logger.info(f"persisted: {persisted_data}")


def dump_persisted_data() -> None:
    with persisted_data_yml.open("w", encoding="utf-8") as fp:
        fp.write(yaml.dump(persisted_data))


def github_actions_set_env(key: str, value: Any) -> None:
    if os.getenv("GITHUB_ACTIONS") != "true":
        return
    GITHUB_ENV = os.getenv("GITHUB_ENV")
    if not GITHUB_ENV:
        logger.error("GITHUB_ENV not set or empty")
        return
    with open(GITHUB_ENV, "a") as fp:
        print(f"{key}={value}", file=fp)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-j", "--jobs", type=int, default=1)
    parser.add_argument("--regenerate", action="store_true")
    args = parser.parse_args()

    load_persisted_data()
    config, prior_config = load_config()

    github_actions_set_env("LOGFILE", logfile)
    retcode = 0
    try:
        registry, updated_packages, failed_packages, removed_packages = update_registry(
            config.packages, jobs=args.jobs
        )

        # Regenerate all feeds if feed config changes.
        regenerate_all = (
            args.regenerate or prior_config is None or prior_config.feed != config.feed
        )

        if updated_packages:
            logger.info(f"updated: {', '.join(updated_packages)}")
        else:
            logger.info(f"no updates found")
        if failed_packages:
            logger.error(f"failed: {', '.join(failed_packages)}")
            retcode = 1
        if removed_packages:
            remove_outdated_feeds(removed_packages)

        if not (updated_packages or removed_packages or regenerate_all):
            return retcode

        if regenerate_all:
            logger.info("change(s) in feed config detected, regenerating all feeds")
        packages_to_regenerate = config.packages if regenerate_all else updated_packages
        generate_aggregate_feed(registry, config)
        for package in packages_to_regenerate:
            generate_single_package_feed(package, registry[package], config)
        generate_feed_index(registry, config)
    except Exception:
        # On uncaught exception, remove used_config.yml so that all
        # feeds will be regenerated next time.
        used_config_yml.unlink(missing_ok=True)
        logger.critical("unexpected exception", exc_info=True)
        retcode = 1
    else:
        # On normal exit, write config to used_config.yml.
        dump_config(config)
    finally:
        dump_persisted_data()
    return retcode


if __name__ == "__main__":
    sys.exit(main())
