# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Stopping what a run left behind - no Django here, the remote executor uses it too."""
from __future__ import annotations

import os
import signal
from pathlib import Path


def kill_leftovers(private_data_dir: Path) -> int:
    """Stop whatever a run left behind: after a dead worker the whole
    ansible-playbook, after a cancelled or finished one its stragglers.

    ansible-runner starts ansible-playbook on a pty, which makes it the leader
    of its own session: killing that process group takes Ansible's forks and
    whatever they started - a long command, a hung ssh - down with it.  It is
    recognised by the job directory on its command line.  Linux only; without
    /proc there is nothing to look through.
    """
    proc = Path("/proc")
    # The trailing slash keeps job_1 from matching job_12.
    marker = str(private_data_dir).rstrip("/") + "/"
    if not proc.is_dir():
        return 0
    killed = 0
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ")
        except OSError:
            continue
        if marker.encode() not in cmdline:
            continue
        pid = int(entry.name)
        try:
            if os.getpgid(pid) == pid:
                os.killpg(pid, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGKILL)
            killed += 1
        except OSError:  # gone in the meantime, or not ours to signal
            continue
    return killed
