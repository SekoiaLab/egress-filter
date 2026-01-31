"""GitHub Actions hosted runner environment constants.

These are facts about the GitHub-hosted runner environment, independent
of any specific action. They're used for:
- Scoping policy rules to the runner process tree (cgroup)
- Identifying trusted process ancestry (Runner.Worker exe path)
"""

# Cgroup path for processes in the runner's process tree
# Used to distinguish runner processes from Docker containers, Azure agent, etc.
RUNNER_CGROUP = "/system.slice/hosted-compute-agent.service"

# Full path to the Runner.Worker executable
# This process spawns each step and sets GITHUB_* env vars in children
RUNNER_WORKER_EXE = "/home/runner/actions-runner/cached/bin/Runner.Worker"

# Node.js executable path for actions using node24 runtime
# Must match the 'using' field in action.yml
NODE24_EXE = "/home/runner/actions-runner/cached/externals/node24/bin/node"
