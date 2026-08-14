from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from typing import Optional, Sequence


class CommandError(RuntimeError):
    def __init__(self, argv: Sequence[str], returncode: int, stderr: str = ""):
        self.argv = list(argv)
        self.returncode = returncode
        self.stderr = stderr
        msg = f"command failed ({returncode}): {' '.join(self.argv)}"
        if stderr:
            msg += f"\n{stderr.strip()}"
        super().__init__(msg)


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


def run(
    argv: Sequence[str],
    *,
    check: bool = True,
    capture: bool = True,
    timeout: Optional[float] = None,
    env: Optional[dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    merged = None
    if env is not None:
        merged = os.environ.copy()
        merged.update(env)
    proc = subprocess.run(
        list(argv),
        check=False,
        capture_output=capture,
        text=True,
        timeout=timeout,
        env=merged,
    )
    if check and proc.returncode != 0:
        err = proc.stderr or proc.stdout or ""
        raise CommandError(argv, proc.returncode, err)
    return proc


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def parse_speed(text: str) -> int:
    """Parse '8m', '512k', or a raw bit/s integer."""
    raw = text.strip().lower()
    if raw.endswith("g"):
        return int(float(raw[:-1]) * 1_000_000_000)
    if raw.endswith("m"):
        return int(float(raw[:-1]) * 1_000_000)
    if raw.endswith("k"):
        return int(float(raw[:-1]) * 1_000)
    return int(raw)


def format_speed(bps: int) -> str:
    if bps >= 1_000_000_000:
        return f" {bps / 1_000_000_000:4.1f}G"
    if bps >= 1_000_000:
        return f" {bps / 1_000_000:4.1f}M"
    if bps >= 1_000:
        return f" {bps / 1_000:4.0f}k"
    return f" {bps:4d} "


def format_ping(ping: Optional[int]) -> str:
    if ping is None:
        return "  - "
    return f"{ping:3d}ms"
