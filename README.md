# release-feeds

![build status](https://github.com/zmwangx/release-feeds/workflows/update/badge.svg)

This repository contains tools to generate release feeds with GitHub Actions and GitHub Pages for a wide range of open source software, bootstrapped on Debian's [watch](https://wiki.debian.org/debian/watch) infrastructure. Monitoring a package is as easy as adding a package name to the config file; no need to learn another DSL.

## The feeds

All active feed URLs can be found in [docs/feeds.txt](docs/feeds.txt).

## How it works

- You configure in `config.yml` feed metadata and a list of [Debian source packages](https://sources.debian.org/) to monitor;

- The `update.yml` GitHub Actions workflow is run periodically, which invokes `src/update.py`;

- `src/update.py` fetches `debian/watch` for each source package from the sid (unstable, i.e. most up-to-date) distribution and runs [`uscan(1)`](https://manpages.debian.org/buster/devscripts/uscan.1.en.html) to determine the latest version of each package; then it generates/refreshes feeds as necessary. The following feeds are generated:

  - `docs/aggregate.xml`: an aggregate feed for all monitored packages;
  - `docs/<package>.xml`: a separate feed for each package.

  The feeds only contain the latest version for each package, so individual package feeds are always single-entry. The feeds are placed in the unfortunately-named `docs` directory in order to be served by GitHub Pages.

Note: In addition to packages bootstrapped from Debian, you can supply your own watch file for a package as `watch_overrides/<package>`, useful in the following scenarios:

- Debian does not package the software;
- The Debian package does not contain `debian/watch` (e.g. `golang-defaults`);
- The Debian package's watch file does not monitor the latest version for whatever reason (e.g. Debian's `imagemagick` is pegged to v6, whereas the latest release track is v7).

## Copyright

This repo is brought to you by Zhiming Wang <<i@zhimingwang.org>> under WTFPL.
