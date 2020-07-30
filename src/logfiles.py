import datetime
import pathlib
import sys
from typing import List, Tuple


root = pathlib.Path(__file__).parent.parent
filename_template = "%Y-%m-%dT%H.%M.%S%z.log"


def now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def generate_logfile_path() -> pathlib.Path:
    return root / now().strftime(filename_template).replace("+0000", "Z")


def list_logfiles() -> List[Tuple[datetime.datetime, pathlib.Path]]:
    list_ = []
    for file in root.glob("*.log"):
        try:
            timestamp = datetime.datetime.strptime(file.name, filename_template)
            list_.append((timestamp, file))
        except ValueError:
            pass
    return list_


# Remove logfiles older than two weeks.
def trim_logfiles() -> None:
    cutoff = now() - datetime.timedelta(days=14)
    for timestamp, file in list_logfiles():
        if timestamp < cutoff:
            file.unlink()
            print(f"removed {file}", file=sys.stderr)


def main():
    trim_logfiles()


if __name__ == "__main__":
    main()
