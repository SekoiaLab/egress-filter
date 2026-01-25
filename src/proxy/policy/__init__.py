"""Policy parsing and matching engine."""

from .types import Rule, AttrValue, HeaderContext
from .parser import parse_policy, flatten_policy, rule_to_dict
from .matcher import ConnectionEvent, PolicyMatcher, match_rule
from .dns_cache import DNSIPCache
from .enforcer import PolicyEnforcer, Decision, Verdict, ProcessInfo

__all__ = [
    # Types
    "Rule",
    "AttrValue",
    "HeaderContext",
    # Parser
    "parse_policy",
    "flatten_policy",
    "rule_to_dict",
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
