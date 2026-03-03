from __future__ import annotations

from abc import ABC, abstractmethod

from guardintent.config import Config
from guardintent.models import Event, RuleHit


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
    from guardintent.rules.brute_force import BruteForceRule
    from guardintent.rules.ioc_match import IOCMatchRule
    from guardintent.rules.lateral_movement import LateralMovementRule
    from guardintent.rules.privileged_abnormal import PrivilegedAbnormalRule
    from guardintent.rules.rare_process import RareProcessRule

    return [IOCMatchRule, BruteForceRule, PrivilegedAbnormalRule, RareProcessRule, LateralMovementRule]
