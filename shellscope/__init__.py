"""shellscope: parse agent shell commands and enforce deny rules."""
__version__ = "0.1.0"
from .parser import parse_command, EffectReport  # noqa: F401
from .rules import RuleSet, load_rules, Violation  # noqa: F401
