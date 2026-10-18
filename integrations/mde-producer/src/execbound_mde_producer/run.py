# SPDX-License-Identifier: Apache-2.0
"""One cycle, the loop and the command line: `execbound-mde-producer run --config PATH`."""

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from execbound_mde_producer import __version__
from execbound_mde_producer.config import Config, ConfigError, load, read_env, read_token
from execbound_mde_producer.defender import Defender, DefenderError
from execbound_mde_producer.envelope import plan
from execbound_mde_producer.gateway import Answer, post


class TokenRefused(RuntimeError):
    """The gateway refused the producer's token: only an operator's rotation fixes that."""


@dataclass(frozen=True)
class CycleReport:
    posted: int
    duplicates: int
    uncovered: tuple[str, ...]
    refused: dict[str, int] = field(default_factory=dict)


def cycle(
    config: Config,
    defender: Defender,
    token: str,
    *,
    now: datetime,
    version: str,
    poster: Callable[..., Answer] = post,
) -> CycleReport:
    built = plan(config, defender.machines(), now, version)
    posted = duplicates = 0
    refused: Counter[str] = Counter()
    for envelope in built.envelopes:
        answer = poster(config.gateway, token, envelope)
        if answer.status == 202:
            posted += 1
        elif answer.status == 200:
            duplicates += 1
        elif answer.status == 401:
            raise TokenRefused(answer.code or "INVALID_SOURCE")
        else:
            refused[answer.code or f"HTTP_{answer.status}"] += 1
    return CycleReport(posted, duplicates, built.uncovered, dict(refused))


def _log(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="execbound-mde-producer")
    commands = parser.add_subparsers(dest="command", required=True)
    runner = commands.add_parser("run", help="Report every covered host's risk score")
    runner.add_argument("--config", type=Path, required=True)
    runner.add_argument("--once", action="store_true", help="One cycle, then exit")
    args = parser.parse_args(argv)
    try:
        config = load(args.config)
        client = Defender(read_env(config.defender_env))
        token = read_token(config.token_file)
    except ConfigError as error:
        _log("refused", reason=str(error))
        return 2
    except KeyError:
        _log("refused", reason="MISSING_CREDENTIAL")
        return 2
    while True:
        started = time.monotonic()
        wait = config.interval_seconds
        advised_wait = 0
        exit_code = 0
        try:
            report = cycle(config, client, token, now=datetime.now(UTC), version=__version__)
            if report.refused or report.uncovered:
                exit_code = 1
            _log(
                "cycle",
                posted=report.posted,
                duplicates=report.duplicates,
                uncovered=list(report.uncovered),
                refused=report.refused,
            )
        except TokenRefused as error:
            _log("stopped", code=str(error))
            return 2
        except DefenderError as error:
            exit_code = 1
            _log("defender", status=error.status, message=str(error))
            if error.retry_after is not None:
                advised_wait = error.retry_after
        if args.once:
            return exit_code
        time.sleep(max(advised_wait, wait - (time.monotonic() - started)))
