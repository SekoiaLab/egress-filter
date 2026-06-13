"""GitHub Actions hosted runner environment constants.

These are facts about the GitHub-hosted runner environment, independent
of any specific action. They're used for:
- Scoping policy rules to the runner process tree (cgroup)
- Identifying trusted process ancestry (Runner.Worker exe path)
"""

import os
import re

# Cgroup path for processes in the runner's process tree, used to distinguish
# runner processes from Docker containers, the Azure agent, etc.
#
# This is only a *fallback*: at startup the proxy derives the actual cgroup
# from the live Runner.Worker (see validate_runner_environment) so a rename of
# the hosted-compute-agent service adapts automatically instead of silently
# breaking every rule. Read the effective value via runner_cgroup().
DEFAULT_RUNNER_CGROUP = "/system.slice/hosted-compute-agent.service"
# Back-compat alias for importers/tests that want the static default.
RUNNER_CGROUP = DEFAULT_RUNNER_CGROUP

_runner_cgroup = DEFAULT_RUNNER_CGROUP


def runner_cgroup() -> str:
    """Effective runner cgroup (derived at startup; falls back to the default)."""
    return _runner_cgroup


def _set_runner_cgroup(value: str) -> None:
    global _runner_cgroup
    _runner_cgroup = value

# Runner exe paths vary by installation method: "cached", "extracted", a
# version directory like "2.331.0", or nested like "cached/2.334.0".
# Match the stable prefix + suffix with one or more directories between.
_RUNNER_BASE = r"/home/runner/actions-runner/(?:[^/]+/)+"
_RUNNER_WORKER_RE = re.compile(_RUNNER_BASE + r"bin/Runner\.Worker$")
_NODE24_RE = re.compile(_RUNNER_BASE + r"externals/node24/bin/node$")


def is_runner_worker(exe: str) -> bool:
    return _RUNNER_WORKER_RE.match(exe) is not None


def is_node24(exe: str) -> bool:
    return _NODE24_RE.match(exe) is not None


def check_runner_ancestry(exe_paths: list[str]) -> list[str]:
    """Structural sanity check on a process ancestry (self -> outward).

    Position-independent (unlike asserting fixed indices, which broke on runner
    image updates): we only require that Runner.Worker and the node24 action
    runtime are both present and that node24 is a *descendant* of Runner.Worker
    (i.e. appears earlier in the self-outward list). This survives wrappers
    being added to or removed from the runner process tree.

    Returns a list of error messages (empty if the structure looks right).
    """
    node24_idx = next((i for i, exe in enumerate(exe_paths) if is_node24(exe)), -1)
    worker_idx = next((i for i, exe in enumerate(exe_paths) if is_runner_worker(exe)), -1)

    errors = []
    if worker_idx < 0:
        errors.append(f"Runner.Worker not found in ancestry: {exe_paths}")
    if node24_idx < 0:
        errors.append(f"node24 action runtime not found in ancestry: {exe_paths}")
    if worker_idx >= 0 and node24_idx >= 0 and node24_idx >= worker_idx:
        errors.append(
            f"node24 (idx {node24_idx}) should be a descendant of Runner.Worker "
            f"(idx {worker_idx}); ancestry: {exe_paths}"
        )
    return errors


def validate_runner_environment() -> list[str]:
    """Confirm the proxy can attribute connections to the runner, and derive
    the runner cgroup. Returns a list of error messages (empty if valid).

    Rather than asserting a fixed process-tree shape (which is brittle across
    runner updates), this validates the *capability* the security model relies
    on: it derives the runner cgroup from the live Runner.Worker, then runs the
    exact trusted-env walk that authenticates the control socket and confirms it
    recovers this action's own GITHUB_ACTION_REPOSITORY. If that works, the tree
    shape doesn't matter. A structural check is used only as a fallback when the
    functional self-test can't run (e.g. no GITHUB_ACTION_REPOSITORY, as on some
    forks).
    """
    # Lazy import to avoid a circular dependency (proc.py imports from gha.py).
    from proxy.proc import (
        get_process_ancestry,
        get_cgroup_path,
        get_trusted_github_env,
    )

    ancestry = get_process_ancestry(os.getpid(), max_depth=10)
    exe_paths = [exe for _, exe in ancestry]
    node24_idx = next((i for i, exe in enumerate(exe_paths) if is_node24(exe)), -1)
    worker_idx = next((i for i, exe in enumerate(exe_paths) if is_runner_worker(exe)), -1)

    # Derive the runner cgroup from Runner.Worker so the rest of the proxy
    # (is_runner_process + the cgroup= injected on every rule) adapts to a
    # service rename instead of breaking.
    if worker_idx >= 0:
        worker_cgroup = get_cgroup_path(ancestry[worker_idx][0])
        if worker_cgroup:
            _set_runner_cgroup(worker_cgroup)

    # Functional self-test: the trusted-env walk (the control-socket auth
    # mechanism) must recover our own action repo from the action runtime.
    expected_repo = os.environ.get("GITHUB_ACTION_REPOSITORY", "")
    if expected_repo and node24_idx >= 0 and worker_idx >= 0:
        trusted = get_trusted_github_env(ancestry[node24_idx][0])
        got_repo = trusted.get("GITHUB_ACTION_REPOSITORY", "")
        if got_repo == expected_repo:
            return []  # capability confirmed; tree shape is adequate by definition
        return [
            f"trusted-env self-test failed: recovered "
            f"GITHUB_ACTION_REPOSITORY={got_repo!r}, expected {expected_repo!r} "
            f"(cgroup={runner_cgroup()}; ancestry: {exe_paths})"
        ]

    # Couldn't self-test (no repo / missing process) -> structural fallback.
    return check_runner_ancestry(exe_paths)
