"""Exercise diagnostic resource limits with tiny processes, never a compiler."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

RUNNER = Path(__file__).resolve().parents[1] / "scripts/limited_build.py"


@unittest.skipUnless(sys.platform == "linux", "Linux resource limits")
class LimitedBuildTests(unittest.TestCase):
    def run_command(self, source, *options):
        return subprocess.run(
            [sys.executable, str(RUNNER), "--memory-mib", "128", "--reserve-mib", "256",
             "--seconds", "3", *options, "--", sys.executable, "-c", source],
            capture_output=True, text=True, timeout=12)

    def test_success_and_exit_code(self):
        result = self.run_command("print('bounded-child')")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bounded-child", result.stdout)
        self.assertEqual(self.run_command("raise SystemExit(7)").returncode, 7)

    def test_insufficient_reserve_skips_child(self):
        result = self.run_command("print('must-not-run')", "--reserve-mib", "1000000000")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("insufficient available memory", result.stderr)
        self.assertNotIn("must-not-run", result.stdout)

    def test_address_space_cap(self):
        # Allocation is rejected by RLIMIT_AS before 256 MiB can be committed.
        result = self.run_command("bytearray(256 * 1024 * 1024)")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("MemoryError", result.stderr)

    def assert_stopped(self, pid):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            stat = Path(f"/proc/{pid}/stat")
            if not stat.exists() or stat.read_text().split(")", 1)[1].split()[0] == "Z":
                return
            time.sleep(0.02)
        self.fail(f"Diagnostic descendant {pid} survived cleanup")

    def test_deadline_and_grandchild_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="control-budget-test-") as directory:
            child_file = Path(directory) / "child.pid"
            child = ("import os,signal,time; from pathlib import Path; "
                     "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                     f"Path({str(child_file)!r}).write_text(str(os.getpid())); time.sleep(30)")
            source = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(30)"
            result = self.run_command(source, "--seconds", "1")
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertTrue(child_file.exists(), result.stderr)
            self.assert_stopped(int(child_file.read_text()))

    def test_supervisor_termination_cleans_child(self):
        with tempfile.TemporaryDirectory(prefix="control-budget-test-") as directory:
            child_file = Path(directory) / "child.pid"
            source = ("import os,time; from pathlib import Path; "
                      f"Path({str(child_file)!r}).write_text(str(os.getpid())); time.sleep(30)")
            process = subprocess.Popen(
                [sys.executable, str(RUNNER), "--memory-mib", "128", "--reserve-mib", "256",
                 "--seconds", "5", "--", sys.executable, "-c", source],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 3
                while not child_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(child_file.exists())
                process.send_signal(signal.SIGTERM)
                _, error = process.communicate(timeout=7)
                self.assertEqual(process.returncode, 124, error)
                self.assert_stopped(int(child_file.read_text()))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if child_file.exists():
                    try:
                        os.kill(int(child_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
