"""
Rule of Two Engine:
Never allow an AI agent to simultaneously hold more than 2 of the 3
dangerous capabilities:
  A) Access to confidential data
  B) External network communication
  C) Reading untrusted/external content

This is the core architectural safety primitive.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


class PolicyViolationError(Exception):
    pass


@dataclass
class TaskPolicy:
    access_confidential_db: bool = False
    external_network: bool = False
    read_untrusted_content: bool = False
    task_name: Optional[str] = None

    def active_capabilities(self) -> list[str]:
        caps = []
        if self.access_confidential_db:
            caps.append("A:confidential_db")
        if self.external_network:
            caps.append("B:external_network")
        if self.read_untrusted_content:
            caps.append("C:untrusted_content")
        return caps

    def validate(self) -> None:
        """Raise PolicyViolationError if all 3 capabilities are active at once."""
        active = self.active_capabilities()
        if len(active) >= 3:
            raise PolicyViolationError(
                f"Rule of Two violation for task '{self.task_name or 'unnamed'}': "
                f"All 3 dangerous capabilities active simultaneously: {active}. "
                f"Remove at least one capability before proceeding."
            )

    @property
    def is_safe(self) -> bool:
        return len(self.active_capabilities()) < 3

    def describe(self) -> str:
        active = self.active_capabilities()
        status = "SAFE" if self.is_safe else "VIOLATION"
        return (
            f"[{status}] Task: {self.task_name or 'unnamed'} | "
            f"Active capabilities ({len(active)}/3): {active}"
        )


class RuleOfTwo:
    """
    Policy manager for enforcing the Rule of Two across an agent session.

    Usage:
        policy = RuleOfTwo()

        # RAG task — DB access + untrusted content, but NO external network
        policy.set_task(
            access_confidential_db=True,
            external_network=False,
            read_untrusted_content=True,
            task_name="rag_search"
        )
        policy.validate()  # passes

        # Unsafe task — all 3 active
        policy.set_task(
            access_confidential_db=True,
            external_network=True,
            read_untrusted_content=True,
            task_name="web_then_db"
        )
        policy.validate()  # raises PolicyViolationError
    """

    # Predefined safe task presets
    PRESETS: dict[str, dict] = {
        "rag_search": {
            "access_confidential_db": True,
            "external_network": False,
            "read_untrusted_content": True,
        },
        "web_research": {
            "access_confidential_db": False,
            "external_network": True,
            "read_untrusted_content": True,
        },
        "external_api_report": {
            "access_confidential_db": False,
            "external_network": True,
            "read_untrusted_content": False,
        },
        "internal_data_analysis": {
            "access_confidential_db": True,
            "external_network": False,
            "read_untrusted_content": False,
        },
        "code_generation": {
            "access_confidential_db": False,
            "external_network": False,
            "read_untrusted_content": True,
        },
    }

    def __init__(self):
        self._current_policy: Optional[TaskPolicy] = None
        self._history: list[TaskPolicy] = []

    def set_task(
        self,
        task_name: Optional[str] = None,
        access_confidential_db: bool = False,
        external_network: bool = False,
        read_untrusted_content: bool = False,
    ) -> TaskPolicy:
        policy = TaskPolicy(
            access_confidential_db=access_confidential_db,
            external_network=external_network,
            read_untrusted_content=read_untrusted_content,
            task_name=task_name,
        )
        self._current_policy = policy
        self._history.append(policy)
        return policy

    def use_preset(self, preset_name: str, task_name: Optional[str] = None) -> TaskPolicy:
        if preset_name not in self.PRESETS:
            raise ValueError(
                f"Unknown preset '{preset_name}'. "
                f"Available: {list(self.PRESETS.keys())}"
            )
        kwargs = self.PRESETS[preset_name].copy()
        kwargs["task_name"] = task_name or preset_name
        return self.set_task(**kwargs)

    def validate(self) -> None:
        if self._current_policy is None:
            raise PolicyViolationError("No task policy set. Call set_task() first.")
        self._current_policy.validate()

    def describe(self) -> str:
        if self._current_policy is None:
            return "No active task policy."
        return self._current_policy.describe()

    @property
    def current_policy(self) -> Optional[TaskPolicy]:
        return self._current_policy
