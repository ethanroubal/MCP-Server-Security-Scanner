"""Trusted Docker sidecar. Shares only the target PID namespace; owns its private trace volume.

Only this container receives SYS_PTRACE. The target keeps no capabilities and has no access
or write permissions to these logs, including through /proc (different UID).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    ready = Path("/proc/1/root/tmp/mcpiranha-launcher-ready")
    deadline = time.monotonic() + 10
    while not ready.exists():
        if time.monotonic() > deadline:
            print(json.dumps({"error": "trusted launcher did not become ready"}), flush=True)
            return 1
        time.sleep(0.02)
    trace = subprocess.Popen(
        [
            "strace",
            "-f",
            "-ttt",
            "-yy",
            "-s",
            "512",
            "-e",
            "trace=open,openat,openat2,close,close_range,dup,dup2,dup3,fcntl,unshare,"
            "read,pread64,readv,preadv,preadv2,mmap,link,linkat,rename,renameat,renameat2,unlink,unlinkat,"
            "chdir,fchdir,clone,clone3,fork,vfork,connect,sendto,sendmsg,sendmmsg,execve,execveat,kill,ptrace",
            "-e",
            "raw=read,pread64,readv,preadv,preadv2",
            "-o",
            sys.argv[1],
            "-p",
            "1",
        ],
        stderr=subprocess.DEVNULL,
    )
    while True:
        status = Path("/proc/1/status").read_text()
        if any(
            line.startswith("TracerPid:") and line.split()[1] != "0" for line in status.splitlines()
        ):
            print(
                json.dumps({"ready": True, "collector_pid": os.getpid(), "tracer_pid": trace.pid}),
                flush=True,
            )
            return trace.wait()
        if trace.poll() is not None or time.monotonic() > deadline:
            trace.terminate()
            print(json.dumps({"error": "strace could not attach"}), flush=True)
            return 1
        time.sleep(0.02)


if __name__ == "__main__":
    raise SystemExit(main())
