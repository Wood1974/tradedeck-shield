"""Offline, verified backup and restore for the single-instance SQLite deployment.

Stop API writes for the duration of backup. SQLite backup snapshots only the
database; the photograph directory has no matching transaction boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_snapshot(database: bytes, originals: dict[str, bytes]) -> None:
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / "shield.db"
        snapshot.write_bytes(database)
        with sqlite3.connect(snapshot) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("sqlite_integrity_check_failed")
            for relative, expected in connection.execute("SELECT original_path,photo_sha256 FROM evidence"):
                if relative not in originals:
                    raise ValueError(f"missing_original:{relative}")
                if digest(originals[relative]) != expected:
                    raise ValueError(f"original_hash_mismatch:{relative}")


def safe_original_name(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(path.parts) and not path.is_absolute() and all(part not in {".", ".."} for part in path.parts) and name == str(path)


def backup(database: Path, storage: Path, archive: Path) -> None:
    if not database.is_file() or not storage.is_dir():
        raise ValueError("database_and_storage_required")
    if archive.exists():
        raise FileExistsError(archive)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / "shield.db"
        with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as source, sqlite3.connect(snapshot) as target:
            source.backup(target)
        db_bytes = snapshot.read_bytes()
        originals: dict[str, bytes] = {}
        for path in sorted(storage.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"symlink_in_storage:{path}")
            if path.is_file():
                relative = path.relative_to(storage).as_posix()
                if not safe_original_name(relative):
                    raise ValueError(f"unsafe_original_path:{relative}")
                originals[relative] = path.read_bytes()
        validate_snapshot(db_bytes, originals)
        manifest = {"format": 1, "created_at": datetime.now(timezone.utc).isoformat(),
                    "files": {"shield.db": digest(db_bytes),
                              **{f"storage/{name}": digest(data) for name, data in originals.items()}}}
        archive.parent.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
                bundle.writestr("manifest.json", json.dumps(manifest, sort_keys=True))
                bundle.writestr("shield.db", db_bytes)
                for name, data in originals.items():
                    bundle.writestr(f"storage/{name}", data)
        except Exception:
            archive.unlink(missing_ok=True)
            raise


def verify(archive: Path) -> tuple[bytes, dict[str, bytes]]:
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if len(names) != len(set(names)) or "manifest.json" not in names:
            raise ValueError("duplicate_or_missing_manifest")
        manifest = json.loads(bundle.read("manifest.json"))
        files = manifest.get("files", {})
        if manifest.get("format") != 1 or "shield.db" not in files or set(names) != set(files) | {"manifest.json"}:
            raise ValueError("invalid_backup_manifest")
        if any(not (name == "shield.db" or
                    (name.startswith("storage/") and safe_original_name(name.removeprefix("storage/"))))
               for name in files):
            raise ValueError("unsafe_backup_path")
        data = {name: bundle.read(name) for name in files}
        if any(digest(contents) != files[name] for name, contents in data.items()):
            raise ValueError("backup_hash_mismatch")
    database = data.pop("shield.db")
    originals = {name.removeprefix("storage/"): contents for name, contents in data.items()}
    validate_snapshot(database, originals)
    return database, originals


def restore(archive: Path, database: Path, storage: Path) -> None:
    if database.exists() or storage.exists():
        raise FileExistsError("restore_targets_must_be_empty")
    db_bytes, originals = verify(archive)
    database.parent.mkdir(parents=True, exist_ok=True)
    storage.mkdir(parents=True, exist_ok=False)
    try:
        for name, contents in originals.items():
            path = storage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
        with database.open("xb") as target:
            target.write(db_bytes)
    except Exception:
        # Leave partial data visible for inspection. Never start the service
        # after a failed restore; use new empty targets for the next attempt.
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Shield offline backup, verification and empty-target restore")
    parser.add_argument("action", choices=["backup", "verify", "restore"])
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--storage", type=Path)
    args = parser.parse_args()
    if args.action != "verify" and (args.database is None or args.storage is None):
        parser.error("--database and --storage are required")
    if args.action == "backup":
        backup(args.database, args.storage, args.archive)
    elif args.action == "restore":
        restore(args.archive, args.database, args.storage)
    else:
        verify(args.archive)
    print(f"Shield {args.action} verified: {args.archive}")


if __name__ == "__main__":
    main()
