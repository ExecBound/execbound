# SPDX-License-Identifier: AGPL-3.0-only
"""File-only replay entry point. No live authority or environment bootstrap."""

import json
import os
import stat
from pathlib import Path

from execbound.policy.models import BundleContent
from execbound.replay.models import MAX_EXPORT_BYTES, TrustedHead
from execbound.replay.report import ReplayReport, render_report, report_json
from execbound.replay.simulate import simulate
from execbound.replay.verify import parse_export, verify_export
from execbound.requests import _reject_number, _unique_object

MAX_CANDIDATE_BYTES = 1024 * 1024
CHECKPOINT_NOTICE = (
    "A head accompanying its export proves internal consistency only. "
    "An independently retained checkpoint is needed to establish the expected history.\n"
)


class ReplayFileError(ValueError):
    def __init__(self) -> None:
        super().__init__("Replay files unavailable")


def read_bounded(path: Path, limit: int) -> bytes:
    """Reject streams/devices and enforce the bound even if a file grows during read."""
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Invalid file")
    with path.open("rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Invalid file")
        raw = handle.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise ValueError("File exceeds bound")
    return raw


def strict_json(raw: bytes) -> None:
    json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_float=_reject_number,
        parse_constant=_reject_number,
    )


def remove_owned(path: Path, owned: os.stat_result) -> None:
    try:
        current = path.lstat()
        if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
            path.unlink()
    except FileNotFoundError:
        pass


def write_new(path: Path, data: bytes, *, mode: int = 0o666) -> os.stat_result:
    """Write only inside a newly created private output directory, or, given a private `mode`,
    a new file that is private itself. The umask still applies, as it always did."""
    owned = None
    try:
        with open(path, "xb", opener=lambda name, flags: os.open(name, flags, mode)) as handle:
            owned = os.fstat(handle.fileno())
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return owned
    except BaseException:
        if owned is not None:
            remove_owned(path, owned)
        raise


def run_replay(
    source: Path,
    checkpoint: Path,
    output: Path,
    candidate: Path | None = None,
) -> ReplayReport:
    created = False
    owned: os.stat_result | None = None
    destinations: list[tuple[Path, os.stat_result]] = []
    try:
        source, checkpoint, output = Path(source), Path(checkpoint), Path(output)
        inputs = [source, checkpoint] + ([Path(candidate)] if candidate is not None else [])
        if any(output.resolve() == path.resolve() for path in inputs) or os.path.lexists(output):
            raise ValueError("Invalid output")
        export = parse_export(read_bounded(source, MAX_EXPORT_BYTES))
        raw_head = read_bounded(checkpoint, 4096)
        strict_json(raw_head)
        head = TrustedHead.model_validate_json(raw_head)
        hypothetical = None
        if candidate is not None:
            raw_candidate = read_bounded(Path(candidate), MAX_CANDIDATE_BYTES)
            strict_json(raw_candidate)
            hypothetical = BundleContent.model_validate_json(raw_candidate)
        report = simulate(verify_export(export, head), hypothetical)
        artifacts = {
            "report.json": report_json(report).encode("utf-8"),
            "report.md": (render_report(report) + "\n" + CHECKPOINT_NOTICE).encode("utf-8"),
        }
        if any(len(raw) > MAX_EXPORT_BYTES for raw in artifacts.values()):
            raise ValueError("Report exceeds bound")
        # mkdir is the exclusive ownership claim. No parent directory is created.
        output.mkdir(mode=0o700)
        created, owned = True, output.stat()
        for name, raw in artifacts.items():
            destination = output / name
            destinations.append((destination, write_new(destination, raw)))
        return report
    # Raise the generic error outside the handler; a nested one may name a private path.
    except Exception:  # nosec B110 - a nested exception may name a private path
        pass
    # Deliberately omit underlying parser/filesystem errors, which can contain secrets.
    if created and owned is not None:
        try:
            current = output.lstat()
            if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                for destination, identity in destinations:
                    remove_owned(destination, identity)
                output.rmdir()
        except OSError:
            pass
    raise ReplayFileError()
