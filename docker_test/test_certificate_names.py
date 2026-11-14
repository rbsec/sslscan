#!/usr/bin/env python3
"""Check certificate names using a local TLS server, without Docker.

Run after building sslscan: python3 docker_test/test_certificate_names.py
"""

import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET


class CertificateNamesTest(unittest.TestCase):
    def test_certificate_names(self):
        scanner = Path(os.environ.get("SSLSCAN", "./sslscan")).resolve()
        cases = [
            ("/CN=single", "/CN=single", "single", "single"),
            ("/C=GB/O=Test/CN=first/CN=second", "/C=GB/O=Test/CN=first/CN=second",
             "/C=GB/O=Test/CN=first/CN=second", "/C=GB/O=Test/CN=first/CN=second"),
            ("/C=GB/O=NoCN", "/C=GB/O=NoCN", "/C=GB/O=NoCN", "/C=GB/O=NoCN"),
            ("/CN=leaf", "/CN=issuer1/CN=issuer2", "leaf", "/CN=issuer1/CN=issuer2"),
            ("/CN=leaf1/CN=leaf2", "/CN=issuer", "/CN=leaf1/CN=leaf2", "issuer"),
            ("/CN=first+CN=second", "/CN=issuer", "/CN=first+CN=second", "issuer"),
            ("/CN=shared/CN=leaf", "/CN=shared/CN=issuer",
             "/CN=shared/CN=leaf", "/CN=shared/CN=issuer"),
        ]
        for subject, issuer, expected_subject, expected_issuer in cases:
            with self.subTest(subject=subject, issuer=issuer), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)

                def openssl(*args):
                    subprocess.run(["openssl", *args], cwd=root, check=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

                openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", issuer, "-keyout", "ca.key", "-out", "ca.pem")
                openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", subject,
                        "-keyout", "leaf.key", "-out", "leaf.csr")
                openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                        "-set_serial", "1", "-days", "1", "-out", "leaf.pem")
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = sock.getsockname()[1]
                server = subprocess.Popen(
                    ["openssl", "s_server", "-accept", f"127.0.0.1:{port}", "-key",
                     str(root / "leaf.key"), "-cert", str(root / "leaf.pem"), "-quiet"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    for _ in range(100):
                        if server.poll() is not None:
                            self.fail("Local TLS server exited before the scan")
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                break
                        except OSError:
                            time.sleep(0.05)
                    else:
                        self.fail("Local TLS server did not start")
                    report = root / "report.xml"
                    result = subprocess.run(
                        [str(scanner), "--no-colour", "--tls12", "--no-ciphersuites",
                         "--no-groups", "--no-heartbleed", "--no-compression", "--no-fallback",
                         "--no-renegotiation", f"--xml={report}", f"127.0.0.1:{port}"],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    cert = ET.parse(report).find(".//certificate[@type='short']")
                    self.assertIsNotNone(cert, result.stdout)
                    self.assertEqual(cert.findtext("subject"), expected_subject)
                    self.assertEqual(cert.findtext("issuer"), expected_issuer)
                    self.assertEqual(cert.findtext("self-signed"),
                                     "true" if subject == issuer else "false")
                    self.assertIn(f"Subject:  {expected_subject}", result.stdout)
                    self.assertIn(f"Issuer:   {expected_issuer}", result.stdout)
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()


if __name__ == "__main__":
    unittest.main()
