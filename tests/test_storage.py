
import pytest

from dlp.storage import initialize_storage, route_file, ZONES


def test_initialize_storage_creates_all_zones():
    initialize_storage()

    assert all(path.is_dir() for path in ZONES.values())


def test_route_file_moves_file_to_quarantine(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_text("Synthetic test content", encoding="utf-8")

    destination = route_file(source, "quarantine")

    assert destination.exists()
    assert destination.read_text(encoding="utf-8") == "Synthetic test content"
    assert not source.exists()


def test_unknown_zone_is_rejected(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_text("Synthetic content", encoding="utf-8")

    with pytest.raises(ValueError):
        route_file(source, "unknown")

    assert source.exists()


def test_existing_destination_is_not_overwritten(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_text("New content", encoding="utf-8")

    destination = ZONES["quarantine"] / source.name
    initialize_storage()
    destination.write_text("Existing content", encoding="utf-8")

    try:
        with pytest.raises(FileExistsError):
            route_file(source, "quarantine")

        assert destination.read_text(encoding="utf-8") == "Existing content"
        assert source.exists()
    finally:
        destination.unlink(missing_ok=True)
