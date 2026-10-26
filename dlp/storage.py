
from pathlib import Path
import shutil


PROJECT_ROOT = Path(__file__).resolve().parent.parent

STORAGE_ROOT = PROJECT_ROOT / "data" / "storage"

ZONES = {
    "incoming": STORAGE_ROOT / "incoming",
    "approved": STORAGE_ROOT / "approved",
    "quarantine": STORAGE_ROOT / "quarantine",
    "blocked": STORAGE_ROOT / "blocked",
}


def initialize_storage() -> None:
    """Create the storage-zone directories if they do not exist."""
    for directory in ZONES.values():
        directory.mkdir(parents=True, exist_ok=True)


def route_file(source: Path, destination_zone: str) -> Path:
    """Move a file into the selected storage zone."""
    if destination_zone not in ZONES:
        raise ValueError(f"Unknown storage zone: {destination_zone}")

    source = Path(source)

    if not source.is_file():
        raise FileNotFoundError(f"Source file not found: {source}")

    initialize_storage()

    destination = ZONES[destination_zone] / source.name

    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination are the same file")

    if destination.exists():
        raise FileExistsError(
            f"A file named {source.name} already exists in "
            f"the {destination_zone} zone"
        )

    shutil.move(str(source), str(destination))

    return destination
