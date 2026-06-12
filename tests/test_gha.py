"""Tests for GitHub runner environment exe path patterns."""

import pytest

from proxy.policy.gha import is_node24, is_runner_worker


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
