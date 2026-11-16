from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolEvent:
    name: str
    args: dict
    result: str


@dataclass
class Transcript:
    task_id: str
    prompt: str
    answer: str
    events: list[ToolEvent] = field(default_factory=list)

    @classmethod
    def from_sandbox(cls, task, answer: str, sandbox) -> "Transcript":
        return cls(task.id, task.prompt, answer,
                   [ToolEvent(c.name, c.args, c.result) for c in sandbox.calls])

    def to_dict(self, max_result: int = 300) -> dict:
        return {
            "task": self.task_id, "prompt": self.prompt, "answer": self.answer,
            "trace": [{"tool": e.name, "args": e.args, "result": e.result[:max_result]}
                      for e in self.events],
        }
