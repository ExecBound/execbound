# SPDX-License-Identifier: AGPL-3.0-only
"""The files whose tests take the machine's timing lock are handed to a worker first.

`--dist loadfile` hands each worker whole files, and xdist orders the files by how many tests
they hold, largest first, on the assumption that a file's length follows its count. The files
that take the timing lock break that assumption: each measured section first waits up to three
minutes for a quiet machine and then queues behind every other suite's measured sections, so a
file of two tests can outlast a file of two hundred. Handed out last, as files of one or two
tests are, they left one worker waiting alone for the last ten minutes of most runs while the
other three sat idle. These tests hold the order the suite's own scheduler gives them, through
the same hook xdist asks for a scheduler, so a file that starts taking the lock without being
named in the conftest fails here rather than quietly slowing every run.
"""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
from xdist.remote import Producer
from xdist.scheduler import LoadFileScheduling

TESTS = Path(__file__).parent
ROOT = TESTS.parent


def timing_lock_files() -> list[str]:
    """Every test file with a function that asks for `timed_alone`, as xdist names the file."""
    found = []
    for path in sorted(TESTS.rglob("*.py")):
        if path.name == "conftest.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                arguments = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                if any(argument.arg == "timed_alone" for argument in arguments):
                    found.append(path.relative_to(ROOT).as_posix())
                    break
    return found


class Settings:
    """What a scheduler reads from the configuration: the distribution, the workers, the reorder."""

    def __init__(self, dist: str, workers: int) -> None:
        self.dist = dist
        self.workers = workers
        self.option = SimpleNamespace(loadscopereorder=True)

    def getvalue(self, name: str):
        return {"dist": self.dist, "tx": [f"{self.workers}*popen"]}[name]


class Worker:
    """A worker as a scheduler sees one: it is sent test indices and may be shut down."""

    def __init__(self, name: str, handed: list[list[int]]) -> None:
        self.gateway = SimpleNamespace(id=name)
        self.handed = handed
        self.sent: list[int] = []
        self.shutting_down = False

    def send_runtest_some(self, indices: list[int]) -> None:
        self.handed.append(list(indices))
        self.sent.extend(indices)

    def shutdown(self) -> None:
        self.shutting_down = True


def scheduler_for(pytestconfig, settings: Settings):
    """The scheduler this suite's session would get: the conftest's, or else xdist's own.

    xdist's own answer to the hook is `trylast`, so whatever the conftest returns comes first
    and xdist's `LoadFileScheduling` is what a session gets when the conftest returns nothing.
    """
    log = Producer("suite-order", enabled=False)
    chosen = pytestconfig.hook.pytest_xdist_make_scheduler(config=settings, log=log)
    return chosen if chosen is not None else LoadFileScheduling(settings, log)


def handed_out(pytestconfig, collection: list[str], workers: int) -> list[str]:
    """Run a whole collection through the scheduler; the files in the order they were handed out.

    Every test is marked complete in turn, as workers would report them, until the scheduler
    has nothing left, and every test must have been sent exactly once.
    """
    handed: list[list[int]] = []
    nodes = [Worker(f"gw{n}", handed) for n in range(workers)]
    scheduler = scheduler_for(pytestconfig, Settings("loadfile", workers))
    for node in nodes:
        scheduler.add_node(node)
    for node in nodes:
        scheduler.add_node_collection(node, collection)
    scheduler.schedule()
    done = {node: 0 for node in nodes}
    while any(done[node] < len(node.sent) for node in nodes):
        for node in nodes:
            if done[node] < len(node.sent):
                scheduler.mark_test_complete(node, node.sent[done[node]])
                done[node] += 1
    assert scheduler.tests_finished
    sent = sorted(index for node in nodes for index in node.sent)
    assert sent == list(range(len(collection))), "a test was dropped or sent twice"
    return [collection[unit[0]].split("::", 1)[0] for unit in handed]


def test_the_files_that_take_the_timing_lock_are_handed_out_before_any_other(pytestconfig):
    timed = timing_lock_files()
    # The three measured sections there are today; finding none would make this vacuous.
    assert len(timed) >= 3, timed
    # Ordinary files of every size around the measured ones, each measured file holding fewer
    # tests than any ordinary one, which is the shape that sent them to the back of the queue.
    ordinary = {
        "tests/test_a_large_file.py": 40,
        "tests/test_a_middling_file.py": 20,
        "tests/test_a_small_file.py": 10,
        "tests/test_another_small_file.py": 10,
        "tests/test_zz_last_by_name.py": 5,
    }
    counts = {**ordinary, **{name: 1 + n % 2 for n, name in enumerate(timed)}}
    collection = [f"{name}::test_{n}" for name in sorted(counts) for n in range(counts[name])]

    order = handed_out(pytestconfig, collection, workers=len(timed) + 1)

    assert sorted(order[: len(timed)]) == sorted(timed), order
    # Everything after them keeps xdist's own order, the most tests first.
    assert order[len(timed) :] == sorted(ordinary, key=lambda name: -ordinary[name]), order


@pytest.mark.parametrize("dist", ["load", "loadscope", "loadgroup", "worksteal"])
def test_only_the_file_distribution_is_reordered(pytestconfig, dist):
    """The suite runs `--dist loadfile`; any other distribution keeps xdist's own scheduler."""
    log = Producer("suite-order", enabled=False)
    settings = Settings(dist, 4)
    assert pytestconfig.hook.pytest_xdist_make_scheduler(config=settings, log=log) is None
