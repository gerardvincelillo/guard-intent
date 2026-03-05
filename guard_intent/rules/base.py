from __future__ import annotations

from abc import ABC, abstractmethod

from guard_intent.config import Config
from guard_intent.models import Event, RuleHit


class BaseRule(ABC):
    rule_id: str
    name: str
    description: str
    mitre_techniques: list[str] = []
    mitre_tactics: list[str] = []

    @abstractmethod
    def run(self, events: list[Event], config: Config, **kwargs) -> list[RuleHit]:
        raise NotImplementedError


def available_rules() -> list[type[BaseRule]]:
    from guard_intent.rules.brute_force import BruteForceRule
    from guard_intent.rules.ioc_match import IOCMatchRule
    from guard_intent.rules.lateral_movement import LateralMovementRule
    from guard_intent.rules.privileged_abnormal import PrivilegedAbnormalRule
    from guard_intent.rules.rare_process import RareProcessRule

    return [IOCMatchRule, BruteForceRule, PrivilegedAbnormalRule, RareProcessRule, LateralMovementRule]

