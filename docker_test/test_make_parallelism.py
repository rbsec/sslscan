#!/usr/bin/env python3
"""Check recursive make job limits without downloading or compiling OpenSSL."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("make"), "make is required")
class MakeParallelismTests(unittest.TestCase):
    def check_build(self, options, expected_jobs=None, nested=False):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            shutil.copyfile(ROOT / "Makefile", work / "Makefile")
            (work / "openssl").mkdir()
            (work / "openssl" / "Makefile").write_text(
                ".PHONY: depend build_libs\n"
                "depend build_libs:\n"
                "\t@printf '%s\\n' '$(MAKEFLAGS)' >> ../flags\n"
                "\t@touch libcrypto.a\n"
            )
            (work / "sslscan.c").touch()
            compiler = work / "compiler"
            compiler.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$MAKEFLAGS" >> flags\n'
            )
            compiler.chmod(0o755)
            arguments = [
                "-o", ".openssl.is.fresh", "static",
                "GIT_VERSION=test", "CC=./compiler",
            ]
            if nested:
                (work / "wrapper.mk").write_text(
                    "all:\n\t$(MAKE) " + " ".join(arguments) + "\n"
                )
                arguments = ["-f", "wrapper.mk"]
            environment = os.environ.copy()
            for name in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "GNUMAKEFLAGS"):
                environment.pop(name, None)
            result = subprocess.run(
                ["make", *options, *arguments], cwd=work, env=environment,
                text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("resetting jobserver", result.stderr)
            self.assertNotIn("jobserver unavailable", result.stderr)
            flags = (work / "flags").read_text().splitlines()
            self.assertEqual(len(flags), 3, result.stdout + result.stderr)
            for child_flags in flags:
                if expected_jobs is not None:
                    self.assertRegex(child_flags, rf"(?:^| )-j{expected_jobs}(?: |$)")
                else:
                    self.assertRegex(child_flags, r"(?:^| )-j\d+(?: |$)")
            if expected_jobs and expected_jobs > 1:
                jobservers = [re.search(r"--jobserver-(?:auth|fds)=\S+", f) for f in flags]
                self.assertTrue(all(jobservers), flags)
                self.assertEqual(len({match.group() for match in jobservers if match}), 1)

    def test_explicit_job_limits(self):
        for jobs in (1, 2, 4):
            with self.subTest(jobs=jobs):
                self.check_build([f"-j{jobs}"], jobs)

    def test_unlimited_jobs(self):
        self.check_build(["-j"], "")

    def test_long_option(self):
        self.check_build(["--jobs=3"], 3)

    def test_inherited_jobserver(self):
        self.check_build(["-j4"], 4, nested=True)

    def test_automatic_parallelism(self):
        self.check_build([])


if __name__ == "__main__":
    unittest.main()
