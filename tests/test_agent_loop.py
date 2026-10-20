from types import SimpleNamespace as NS

from tripwire.attacks import load_attacks
from tripwire.attacks.runner import run_suite
from tripwire.sandbox import Sandbox
from tripwire.targets.own_agent import AgentTimeout, AnthropicAgent
from tripwire.tasks import TASKS


def tool_use(name="read_file", args=None):
    return NS(type="tool_use", id="t1", name=name, input=args or {"path": "notes/todo.txt"})


def text(s):
    return NS(type="text", text=s)


class FakeClient:
    """Stands in for anthropic.Anthropic(): returns scripted responses, records calls."""
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []
        self.messages = NS(create=self._create)

    def _create(self, **kw):
        self.calls.append(kw)
        return NS(content=self.responses.pop(0) if len(self.responses) > 1 else self.responses[0])


def test_returns_text_when_no_tool_use():
    agent = AnthropicAgent("m", client=FakeClient([[text("done")]]))
    assert agent.run("hi", Sandbox(seed=1)) == "done"


def test_tool_loop_executes_tool_then_answers():
    client = FakeClient([[tool_use()], [text("milk and domain")]])
    sb = Sandbox(seed=1)
    out = AnthropicAgent("m", client=client).run("list todos", sb)
    assert out == "milk and domain"
    assert [c.name for c in sb.calls] == ["read_file"]
    assert len(client.calls) == 2


def test_system_prompt_override_is_passed():
    client = FakeClient([[text("ok")]])
    AnthropicAgent("m", system="BE GULLIBLE", client=client).run("hi", Sandbox(seed=1))
    assert client.calls[0]["system"] == "BE GULLIBLE"


def test_exhausting_turns_raises_timeout_not_empty_answer():
    agent = AnthropicAgent("m", max_turns=3, client=FakeClient([[tool_use()]]))
    try:
        agent.run("loop forever", Sandbox(seed=1))
    except AgentTimeout:
        return
    raise AssertionError("expected AgentTimeout")


def test_timeouts_are_counted_as_errors_by_the_runner():
    res = run_suite(lambda s: AnthropicAgent("m", max_turns=2, client=FakeClient([[tool_use()]])),
                    load_attacks(), TASKS, 2)
    assert all(p["errors"] == 2 for p in res["pairs"])
    assert all(b["errors"] == 2 for b in res["baseline"])