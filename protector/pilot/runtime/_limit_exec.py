"""POSIX exec launcher that applies a finite output-file ceiling."""

from __future__ import annotations

import os
import resource
import sys

_EXIT_USAGE = 64
_EXIT_LIMIT_UNAVAILABLE = 78
_EXIT_EXEC_FAILED = 71


def main(arguments: list[str] | None = None) -> int:
    argv = sys.argv[1:] if arguments is None else arguments
    if len(argv) < 3 or argv[1] != "--":
        return _EXIT_USAGE
    try:
        max_bytes = int(argv[0])
    except ValueError:
        return _EXIT_USAGE
    if max_bytes <= 0:
        return _EXIT_USAGE
    command = argv[2:]
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
    except (OSError, ValueError):
        return _EXIT_LIMIT_UNAVAILABLE
    if soft_limit != max_bytes or hard_limit != max_bytes:
        return _EXIT_LIMIT_UNAVAILABLE
    try:
        os.execvpe(command[0], command, os.environ)
    except OSError:
        return _EXIT_EXEC_FAILED
    return _EXIT_EXEC_FAILED


if __name__ == "__main__":  # pragma: no cover - replaced by exec on success
    raise SystemExit(main())
