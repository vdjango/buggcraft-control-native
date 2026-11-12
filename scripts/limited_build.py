"""Run an isolated Linux diagnostic build with explicit memory and elapsed-time budgets."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys


def stop_group(process):
    """Stop every child in this invocation, including children outliving the parent."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The parent may have exited while a grandchild ignores SIGTERM.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--memory-mib", type=int, default=1024)
    parser.add_argument("--reserve-mib", type=int, default=768)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if sys.platform != "linux" or not command:
        parser.error("Linux and an explicit command after -- are required")
    if args.memory_mib < 128 or args.reserve_mib < 256 or not 1 <= args.seconds <= 3600:
        parser.error("Invalid build resource budget")
    memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(memory["MemAvailable"].strip().split()[0]) // 1024
    if available < args.memory_mib + args.reserve_mib:
        raise SystemExit("Diagnostic build skipped: insufficient available memory for the requested reserve")

    def limit_child():
        import resource
        cap = args.memory_mib * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        resource.setrlimit(resource.RLIMIT_CPU, (args.seconds, args.seconds))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.nice(10)

    def terminate(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    process = subprocess.Popen(command, start_new_session=True, preexec_fn=limit_child)
    code = 124
    try:
        code = process.wait(timeout=args.seconds)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        print("Diagnostic build stopped at its resource/deadline budget", file=sys.stderr)
    finally:
        stop_group(process)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
