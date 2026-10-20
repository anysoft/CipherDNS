#!/usr/bin/env python3
"""Verify packaged executables and collect their normalized link reports."""

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import zipfile
import zlib


class VerificationError(Exception):
    """A release package failed validation."""


def required_member(members, name, root, archive):
    matches = [(path, member) for path, member in members if PurePosixPath(path).name == name]
    if not matches:
        kind = "report" if name == "link-report.txt" else "executable"
        raise VerificationError(f"{archive.name}: missing {kind} {root}/{name}")
    if len(matches) != 1:
        raise VerificationError(f"{archive.name}: duplicate archive members named {name}")
    path, member = matches[0]
    if path != f"{root}/{name}":
        raise VerificationError(f"{archive.name}: {name} must be at package root {root}/")
    return member


def read_zip(archive):
    root = archive.name[:-len(".zip")]
    with zipfile.ZipFile(archive) as content:
        members = [(member.filename, member) for member in content.infolist()]
        files = {}
        for name in ("cipherdns.exe", "link-report.txt"):
            member = required_member(members, name, root, archive)
            file_type = stat.S_IFMT(member.external_attr >> 16)
            if member.is_dir() or file_type not in (0, stat.S_IFREG):
                raise VerificationError(f"{archive.name}: {name} must be a regular file")
            files[name] = content.read(member)
    return files["cipherdns.exe"], files["link-report.txt"]


def read_tar(archive):
    root = archive.name[:-len(".tar.gz")]
    with tarfile.open(archive, "r:gz") as content:
        members = [(member.name, member) for member in content.getmembers()]
        files = {}
        for name in ("cipherdns", "link-report.txt"):
            member = required_member(members, name, root, archive)
            if not member.isfile():
                raise VerificationError(f"{archive.name}: {name} must be a regular file")
            data = content.extractfile(member)
            if data is None:
                raise VerificationError(f"{archive.name}: cannot read {name}")
            with data:
                files[name] = data.read()
    return files["cipherdns"], files["link-report.txt"]


def verify_archive(archive):
    try:
        binary, raw_report = read_zip(archive) if archive.suffix == ".zip" else read_tar(archive)
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, zlib.error) as exc:
        raise VerificationError(f"{archive.name}: cannot read ZIP/TAR archive: {exc}") from exc
    try:
        report = raw_report.decode("utf-8").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{archive.name}: link-report.txt is not valid UTF-8") from exc
    lines = report.split("\n")
    verification = [line for line in lines if line.startswith("verification:")]
    if verification != ["verification: PASS"]:
        raise VerificationError(f"{archive.name}: verification field must be exactly 'verification: PASS'")
    digest = hashlib.sha256(binary).hexdigest()
    hashes = [line for line in lines if line.startswith("sha256:")]
    if hashes != [f"sha256: {digest}"]:
        raise VerificationError(f"{archive.name}: sha256 field does not match executable ({digest})")
    return report


def verify_release(directory):
    if not directory.is_dir():
        raise VerificationError(f"{directory}: release directory does not exist")
    archives = sorted(path for path in directory.iterdir()
                      if path.name.endswith((".tar.gz", ".zip")))
    if not archives:
        raise VerificationError(f"{directory}: no ZIP/TAR release archives found")
    summaries = []
    for archive in archives:
        report = verify_archive(archive)
        summaries.append(f"=== {archive.name} ===\n{report}")
    output = directory / "BUILD-REPORTS.txt"
    with output.open("w", encoding="utf-8", newline="\n") as destination:
        destination.write("\n".join(summaries))
    return len(archives)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path("dist"),
                        help="directory of binary release archives (default: dist)")
    args = parser.parse_args()
    try:
        count = verify_release(args.directory)
    except (VerificationError, OSError) as exc:
        print(f"verify-release: {exc}", file=sys.stderr)
        return 1
    print(f"Verified {count} release packages; wrote {args.directory / 'BUILD-REPORTS.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
