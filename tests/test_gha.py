"""Tests for GitHub runner environment exe path patterns."""

import pytest

from proxy.policy.gha import (
    DEFAULT_RUNNER_CGROUP,
    check_runner_ancestry,
    is_node24,
    is_runner_worker,
    runner_cgroup,
)

_BASE = "/home/runner/actions-runner/cached/2.334.0/"
_NODE24 = _BASE + "externals/node24/bin/node"
_WORKER = _BASE + "bin/Runner.Worker"


def test_runner_cgroup_defaults_to_constant():
    # Without startup derivation, the effective cgroup is the static default.
    assert runner_cgroup() == DEFAULT_RUNNER_CGROUP


def test_ancestry_ok_for_current_layout():
    # self -> outward; node24 (action runtime) is a descendant of Runner.Worker.
    exe_paths = [
        "/usr/bin/python3.12", "/usr/bin/bash", "/usr/bin/bash", "/usr/bin/sudo",
        _NODE24, _WORKER,
        _BASE + "bin/Runner.Listener", "/opt/hca/hosted-compute-agent",
    ]
    assert check_runner_ancestry(exe_paths) == []


def test_ancestry_ok_when_wrappers_shift_indices():
    # Extra wrapper processes shift positions — the OLD index assertions broke
    # here; relative-order must still accept it.
    exe_paths = [
        "/usr/bin/python3.12", "/usr/bin/bash", "/usr/bin/some-wrapper",
        "/usr/bin/bash", "/usr/bin/sudo", _NODE24, _WORKER,
        _BASE + "bin/Runner.Listener",
    ]
    assert check_runner_ancestry(exe_paths) == []


def test_ancestry_rejects_missing_runner_worker():
    errs = check_runner_ancestry(["/usr/bin/python3.12", _NODE24, "/usr/bin/bash"])
    assert any("Runner.Worker not found" in e for e in errs)


def test_ancestry_rejects_missing_node24():
    errs = check_runner_ancestry(["/usr/bin/python3.12", "/usr/bin/bash", _WORKER])
    assert any("node24" in e and "not found" in e for e in errs)


def test_ancestry_rejects_node24_not_descendant_of_worker():
    # node24 appearing *outside* Runner.Worker (later in self-outward list) is wrong.
    errs = check_runner_ancestry(["/usr/bin/python3.12", _WORKER, _NODE24])
    assert any("descendant of Runner.Worker" in e for e in errs)


# Layouts observed on GitHub-hosted runners over time
OBSERVED_BASES = [
    "/home/runner/actions-runner/cached/",       # original layout
    "/home/runner/actions-runner/extracted/",    # alternate install method
    "/home/runner/actions-runner/2.331.0/",      # version directory
    "/home/runner/actions-runner/cached/2.334.0/",  # nested (runner >= 2.334)
]


@pytest.mark.parametrize("base", OBSERVED_BASES)
def test_runner_worker_matches_observed_layouts(base):
    assert is_runner_worker(base + "bin/Runner.Worker")


@pytest.mark.parametrize("base", OBSERVED_BASES)
def test_node24_matches_observed_layouts(base):
    assert is_node24(base + "externals/node24/bin/node")


@pytest.mark.parametrize(
    "exe",
    [
        "/home/runner/actions-runner/bin/Runner.Worker",  # no intermediate dir
        "/home/runner/actions-runner/cached/bin/Runner.Listener",
        "/tmp/home/runner/actions-runner/cached/bin/Runner.Worker",  # wrong prefix
        "/home/runner/actions-runner/cached/bin/Runner.Workers",  # suffix overrun
        "",
    ],
)
def test_runner_worker_rejects(exe):
    assert not is_runner_worker(exe)


@pytest.mark.parametrize(
    "exe",
    [
        "/home/runner/actions-runner/externals/node24/bin/node",  # no intermediate dir
        "/home/runner/actions-runner/cached/externals/node20/bin/node",  # wrong node version
        "/usr/bin/node",
        "",
    ],
)
def test_node24_rejects(exe):
    assert not is_node24(exe)
