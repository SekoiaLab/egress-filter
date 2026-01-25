"""Default policy rules for GitHub Actions infrastructure.

These rules allow essential connections that are required for GitHub Actions
to function properly. They can be auto-included with `include: defaults` or
via the enforcer's `include_defaults=True` option.
"""

# Default rules for GitHub-hosted runners
# These are automatically applied unless disabled
GITHUB_ACTIONS_DEFAULTS = """
# =============================================================================
# GitHub Actions Infrastructure Defaults
# =============================================================================
# These rules allow essential connections required for GitHub Actions.
# They are restrictive by design - each rule is scoped to specific executables
# or cgroups where possible to prevent abuse.

# -----------------------------------------------------------------------------
# Local DNS resolver (systemd-resolved on Ubuntu runners)
# All processes need to resolve hostnames via the local resolver.
# -----------------------------------------------------------------------------
[:53/udp]
127.0.0.53

# -----------------------------------------------------------------------------
# GitHub repository operations (actions/checkout, git push, etc.)
# Only allows git executables to access GitHub.
# -----------------------------------------------------------------------------
[*]
github.com exe=`/usr/lib/git-core/git-remote-*`
*.github.com exe=`/usr/lib/git-core/git-remote-*`

# -----------------------------------------------------------------------------
# GitHub Actions services (artifact upload, cache, etc.)
# Only allows the actions-runner node process to access these services.
# -----------------------------------------------------------------------------
[*]
*.actions.githubusercontent.com exe=`/home/runner/actions-runner/*/node*/bin/node`
*.githubusercontent.com exe=`/home/runner/actions-runner/*/node*/bin/node`

# -----------------------------------------------------------------------------
# Azure wireserver (metadata/heartbeat for GitHub-hosted runners)
# Only allows the Azure Linux Agent to access the wireserver.
# -----------------------------------------------------------------------------
[:*]
168.63.129.16 cgroup=`/azure.slice/*`
"""

# Optional presets that users can include
DOCKER_PRESET = """
# =============================================================================
# Docker Registry Access
# =============================================================================
# Allows the Docker daemon to pull images from Docker Hub.

[*]
registry-1.docker.io exe=/usr/bin/dockerd
auth.docker.io exe=/usr/bin/dockerd
*.docker.io exe=/usr/bin/dockerd
production.cloudflare.docker.com exe=/usr/bin/dockerd
"""

# Registry of available presets
PRESETS = {
    "defaults": GITHUB_ACTIONS_DEFAULTS,
    "docker": DOCKER_PRESET,
}


def get_preset(name: str) -> str | None:
    """Get a preset policy by name."""
    return PRESETS.get(name)


def get_defaults() -> str:
    """Get the default GitHub Actions infrastructure rules."""
    return GITHUB_ACTIONS_DEFAULTS
