"""Exercise the release gate with real ZIP/TAR packages and subprocess exits."""

import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


VERIFY_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-release.py"
BOTH_TARGETS = (
    "linux-x86_64-glibc-mostly-static",
    "macos-arm64",
    "macos-x86_64",
    "windows-x86_64",
    "linux-x86_64-musl-static",
    "linux-i686-musl-static",
    "linux-arm64-musl-static",
    "linux-armv7-musl-static",
    "linux-armv5-musl-static",
    "linux-mips-musl-static",
    "linux-mipsel-musl-static",
)
CLIENT_TARGETS = BOTH_TARGETS[:4]


class VerifyReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cipherdns-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.dist = Path(self.temporary.name) / "dist"
        self.dist.mkdir()

    @staticmethod
    def report(binary, newline="\n", verification="PASS", digest=None, mode="BOTH"):
        if digest is None:
            digest = hashlib.sha256(binary).hexdigest()
        return newline.join(
            (
                "CipherDNS link report",
                "version: 0.2.0",
                "build_mode: " + mode,
                "sha256: " + digest,
                "verification: " + verification,
                "",
            )
        ).encode("utf-8")

    def archive(
        self, target="linux-x86_64-musl-static", members=None,
        report=None, root=None, symlink=None,
    ):
        windows = target.startswith("windows-")
        extension = ".zip" if windows else ".tar.gz"
        basename = "cipherdns-0.2.0-" + target
        root = root or basename
        path = self.dist / (basename + extension)
        binary = ("fixture binary for " + target).encode("ascii")
        if members is None:
            if report is None:
                report = self.report(
                    binary, "\r\n" if windows else "\n",
                    mode="CLIENT" if target.endswith("-CLIENT") else "BOTH",
                )
            members = [
                ("cipherdns.exe" if windows else "cipherdns", binary),
                ("link-report.txt", report),
                ("README.md", b"Public release fixture\n"),
            ]
        if windows:
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as content:
                for name, data in members:
                    member = zipfile.ZipInfo(root + "/" + name)
                    member.create_system = 3
                    member.compress_type = zipfile.ZIP_DEFLATED
                    mode = 0o100755 if name == "cipherdns.exe" else 0o100644
                    member.external_attr = (0o120777 if name == symlink else mode) << 16
                    content.writestr(member, data)
        else:
            with tarfile.open(path, "w:gz") as content:
                for name, data in members:
                    member = tarfile.TarInfo(root + "/" + name)
                    member.size = len(data)
                    member.mode = 0o755 if name == "cipherdns" else 0o644
                    if name == symlink:
                        member.type = tarfile.SYMTYPE
                        member.linkname = "README.md"
                        member.size = 0
                        content.addfile(member)
                        continue
                    content.addfile(member, io.BytesIO(data))
        return path

    def verify(self, directory=None):
        return subprocess.run(
            [sys.executable, str(VERIFY_SCRIPT), str(directory or self.dist)],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_rejected(self, archive, reason):
        result = self.verify()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(archive.name, result.stderr)
        # The extension in the package name alone must not satisfy a reason check.
        self.assertRegex(result.stderr.replace(archive.name, "<package>"), reason)
        self.assertFalse((self.dist / "BUILD-REPORTS.txt").exists())

    def test_linux_lf_report_passes(self):
        archive = self.archive()
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = (self.dist / "BUILD-REPORTS.txt").read_bytes()
        self.assertIn(("=== " + archive.name + " ===\n").encode(), summary)
        self.assertIn(b"verification: PASS\n", summary)

    def test_windows_crlf_report_passes_and_summary_uses_lf(self):
        archive = self.archive("windows-x86_64")
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = (self.dist / "BUILD-REPORTS.txt").read_bytes()
        self.assertIn(("=== " + archive.name + " ===\n").encode(), summary)
        self.assertIn(b"verification: PASS\n", summary)
        self.assertNotIn(b"\r\n", summary)

    def test_all_fifteen_release_packages_pass(self):
        archives = [self.archive(target) for target in BOTH_TARGETS]
        archives += [self.archive(target + "-CLIENT") for target in CLIENT_TARGETS]
        # The gate must ignore the external checksum sidecars it shares dist with.
        for archive in archives:
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (self.dist / (archive.name + ".sha256")).write_text(
                digest + "  " + archive.name + "\n", encoding="utf-8"
            )
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = (self.dist / "BUILD-REPORTS.txt").read_text(encoding="utf-8")
        self.assertEqual(summary.count("verification: PASS\n"), 15)
        self.assertEqual(
            [line for line in summary.splitlines() if line.startswith("=== ")],
            ["=== " + archive.name + " ===" for archive in sorted(archives)],
        )

    def test_mismatched_binary_hash_is_rejected(self):
        for target in ("linux-x86_64-musl-static", "windows-x86_64"):
            with self.subTest(target=target):
                report = self.report(b"different binary")
                archive = self.archive(target, report=report)
                self.assert_rejected(archive, r"(?i)sha256|hash")
                archive.unlink()

    def test_verification_fail_is_rejected(self):
        binary = b"fixture binary for windows-x86_64"
        archive = self.archive(
            "windows-x86_64", report=self.report(binary, "\r\n", verification="FAIL")
        )
        self.assert_rejected(archive, r"(?i)verification")

    def test_pass_must_be_a_complete_field(self):
        binary = b"fixture binary for linux-x86_64-musl-static"
        for value in ("PASS-extra", "NOT PASS", "PASS trailing text"):
            with self.subTest(value=value):
                archive = self.archive(report=self.report(binary, verification=value))
                self.assert_rejected(archive, r"(?i)verification")

    def test_hash_must_be_a_complete_field(self):
        binary = b"fixture binary for linux-x86_64-musl-static"
        digest = hashlib.sha256(binary).hexdigest()
        archive = self.archive(report=self.report(binary, digest=digest + "extra"))
        self.assert_rejected(archive, r"(?i)sha256|hash")

    def test_complete_fields_at_start_and_end_of_report_pass(self):
        binary = b"fixture binary for windows-x86_64"
        report = ("verification: PASS\r\nsha256: " + hashlib.sha256(binary).hexdigest()).encode()
        self.archive("windows-x86_64", report=report)
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_duplicate_verification_fields_are_rejected(self):
        binary = b"fixture binary for linux-x86_64-musl-static"
        for extra in (b"verification: PASS\n", b"verification: FAIL\n"):
            with self.subTest(extra=extra):
                archive = self.archive(report=self.report(binary) + extra)
                self.assert_rejected(archive, r"(?i)verification")

    def test_duplicate_hash_fields_are_rejected(self):
        binary = b"fixture binary for linux-x86_64-musl-static"
        for digest in (hashlib.sha256(binary).hexdigest(), "0" * 64):
            with self.subTest(digest=digest):
                report = self.report(binary) + ("sha256: " + digest + "\n").encode()
                archive = self.archive(report=report)
                self.assert_rejected(archive, r"(?i)sha256|hash")

    def test_missing_report_is_rejected(self):
        for target, executable in (
            ("linux-x86_64-musl-static", "cipherdns"),
            ("windows-x86_64", "cipherdns.exe"),
        ):
            with self.subTest(target=target):
                archive = self.archive(target, members=[(executable, b"binary")])
                self.assert_rejected(archive, r"(?i)report")
                archive.unlink()

    def test_missing_executable_is_rejected(self):
        for target in ("linux-x86_64-musl-static", "windows-x86_64"):
            with self.subTest(target=target):
                archive = self.archive(target, members=[("link-report.txt", self.report(b"binary"))])
                self.assert_rejected(archive, r"(?i)executable|cipherdns")
                archive.unlink()

    def test_wrong_platform_executable_is_rejected(self):
        for target, wrong_name in (
            ("linux-x86_64-musl-static", "cipherdns.exe"),
            ("windows-x86_64", "cipherdns"),
        ):
            with self.subTest(target=target):
                archive = self.archive(
                    target,
                    members=[(wrong_name, b"binary"), ("link-report.txt", self.report(b"binary"))],
                )
                self.assert_rejected(archive, r"(?i)executable|cipherdns")
                archive.unlink()

    def test_invalid_zip_and_tar_are_rejected(self):
        for name in ("cipherdns-0.2.0-windows-x86_64.zip", "cipherdns-0.2.0-linux-arm64-musl-static.tar.gz"):
            with self.subTest(name=name):
                archive = self.dist / name
                archive.write_bytes(b"not a valid archive\x00\xff")
                self.assert_rejected(archive, r"(?i)archive|zip|tar")
                archive.unlink()

    def test_invalid_utf8_report_is_rejected(self):
        archive = self.archive("windows-x86_64", report=b"\xff\xfeinvalid report")
        self.assert_rejected(archive, r"(?i)utf-?8|decode|encoding")

    def test_duplicate_critical_basenames_are_rejected(self):
        for target, executable in (
            ("linux-x86_64-musl-static", "cipherdns"),
            ("windows-x86_64", "cipherdns.exe"),
        ):
            for duplicate in (executable, "link-report.txt"):
                with self.subTest(target=target, duplicate=duplicate):
                    binary = b"binary"
                    report = self.report(binary)
                    members = [(executable, binary), ("link-report.txt", report)]
                    members.append(("nested/" + duplicate, report if duplicate == "link-report.txt" else binary))
                    archive = self.archive(target, members=members)
                    self.assert_rejected(archive, r"(?i)duplicate|multiple|path|root")
                    archive.unlink()

    def test_wrong_package_root_is_rejected(self):
        for target in ("linux-x86_64-musl-static", "windows-x86_64"):
            with self.subTest(target=target):
                archive = self.archive(target, root="different-package")
                self.assert_rejected(archive, r"(?i)path|root|expected")
                archive.unlink()

    def test_report_path_traversal_is_rejected_without_extraction(self):
        for target, executable in (
            ("linux-x86_64-musl-static", "cipherdns"),
            ("windows-x86_64", "cipherdns.exe"),
        ):
            with self.subTest(target=target):
                binary = b"binary"
                archive = self.archive(
                    target,
                    members=[(executable, binary), ("../link-report.txt", self.report(binary))],
                )
                self.assert_rejected(archive, r"(?i)path|root|expected")
                self.assertFalse((self.dist / "link-report.txt").exists())
                archive.unlink()

    def test_symlink_critical_members_are_rejected(self):
        for target, executable in (
            ("linux-x86_64-musl-static", "cipherdns"),
            ("windows-x86_64", "cipherdns.exe"),
        ):
            for symlink in (executable, "link-report.txt"):
                with self.subTest(target=target, symlink=symlink):
                    archive = self.archive(target, symlink=symlink)
                    self.assert_rejected(archive, r"(?i)regular|symlink|symbolic|type")
                    archive.unlink()

    def test_failure_does_not_write_a_partial_summary(self):
        self.archive("linux-arm64-musl-static")
        invalid = self.archive("windows-x86_64", report=b"verification: FAIL\r\n")
        self.assert_rejected(invalid, r"(?i)verification|sha256|hash")

    def test_failure_preserves_existing_summary(self):
        archive = self.archive()
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = self.dist / "BUILD-REPORTS.txt"
        previous = summary.read_bytes()
        archive.write_bytes(b"corrupted archive")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(archive.name, result.stderr)
        self.assertEqual(summary.read_bytes(), previous)

    def test_empty_directory_is_rejected(self):
        result = self.verify()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stderr, r"(?i)no.*(archive|package)|empty")
        self.assertFalse((self.dist / "BUILD-REPORTS.txt").exists())

    def test_missing_directory_is_rejected(self):
        missing = self.dist / "missing"
        result = self.verify(missing)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(missing), result.stderr)
        self.assertRegex(result.stderr, r"(?i)directory|exist")

    def test_default_directory_is_dist(self):
        self.archive()
        result = subprocess.run(
            [sys.executable, str(VERIFY_SCRIPT)],
            cwd=self.dist.parent,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.dist / "BUILD-REPORTS.txt").is_file())


if __name__ == "__main__":
    unittest.main()
