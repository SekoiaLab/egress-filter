"""Policy parsing and matching engine."""

from .defaults import RUNNER_DEFAULTS
from .gha import RUNNER_CGROUP, is_node24, is_runner_worker
from .dns_cache import DNSIPCache
from .enforcer import Decision, PolicyEnforcer, ProcessInfo, Verdict
from .matcher import ConnectionEvent, PolicyMatcher, match_rule
from .parser import (
    flatten_policy,
    parse_github_repository,
    parse_policy,
    rule_to_dict,
    substitute_placeholders,
    validate_policy,
)
from .types import (
    SECURE_DEFAULTS,
    AttrValue,
    DefaultContext,
    HeaderContext,
    Rule,
)

__all__ = [
    # Types
    "Rule",
    "AttrValue",
    "HeaderContext",
    "DefaultContext",
    "SECURE_DEFAULTS",
    "RUNNER_CGROUP",
    "is_node24",
    "is_runner_worker",
    "RUNNER_DEFAULTS",
    # Parser
    "parse_policy",
    "flatten_policy",
    "rule_to_dict",
    "substitute_placeholders",
    "parse_github_repository",
    "validate_policy",
    # Matcher
    "ConnectionEvent",
    "PolicyMatcher",
    "match_rule",
    # DNS Cache
    "DNSIPCache",
    # Enforcer
    "PolicyEnforcer",
    "Decision",
    "Verdict",
    "ProcessInfo",
]
