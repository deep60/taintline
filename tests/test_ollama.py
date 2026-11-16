import pytest

from dyepack.attacks import load_attacks
from dyepack.attacks.runner import run_suite
from dyepack.sandbox import Sandbox
from dyepack.targets import make_agent_factory
from dyepack.targets.ollama import OllamaAgent
from dyepack.targets.own_agent import AgentTimeout
from dyepack.tasks import TASKS


def final(text):
    return {"message": {"role": "assistant", "content": text}, "done": True}


def calling(name="read_file", arguments=None):
    args = {"path": "notes/todo.txt"} if arguments is None else arguments
    return {"message": {"role": "assistant", "content": "",
                        "tool_calls": [{"function": {"name": name, "arguments": args}}]}, "done": True}


class FakeResponse:
    def __init__(self, data, fail=False):
        self._data, self._fail = data, fail

    def raise_for_status(self):
        if self._fail:
            raise RuntimeError("HTTP 500")

    def json(self):
        return self._data


class FakeHTTP:
    """Scripted stand-in for httpx.Client. The last scripted response repeats."""
    def __init__(self, responses, fail=False):
        self.responses, self.requests, self.fail = list(responses), [], fail

    def post(self, url, json=None, headers=None):
        self.requests.append({"url": url, "json": json})
        data = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        return FakeResponse(data, self.fail)


def agent(http, **kw):
    return OllamaAgent("llama-test", client=http, **kw)


def test_returns_text_when_no_tool_calls():
    assert agent(FakeHTTP([final("done")])).run("hi", Sandbox(seed=1)) == "done"


def test_uses_native_endpoint_without_streaming():
    http = FakeHTTP([final("ok")])
    agent(http).run("hi", Sandbox(seed=1))
    assert http.requests[0]["url"] == "http://localhost:11434/api/chat"
    assert http.requests[0]["json"]["stream"] is False
    assert http.requests[0]["json"]["messages"][0]["role"] == "system"


def test_tool_loop_runs_tool_and_returns_result_to_the_model():
    http = FakeHTTP([calling(), final("milk and domain")])
    sb = Sandbox(seed=1)
    assert agent(http).run("list todos", sb) == "milk and domain"
    assert [c.name for c in sb.calls] == ["read_file"]
    last = http.requests[1]["json"]["messages"][-1]
    assert last["role"] == "tool" and last["tool_name"] == "read_file" and "milk" in last["content"]


def test_arguments_may_be_a_json_string():
    sb = Sandbox(seed=1)
    agent(FakeHTTP([calling(arguments='{"path": "notes/todo.txt"}'), final("ok")])).run("x", sb)
    assert sb.calls[0].args == {"path": "notes/todo.txt"} and "milk" in sb.calls[0].result


def test_garbage_arguments_do_not_crash_the_loop():
    sb = Sandbox(seed=1)
    out = agent(FakeHTTP([calling(arguments="{not json"), final("sorry")])).run("x", sb)
    assert out == "sorry" and sb.calls[0].result.startswith("error")


def test_tool_call_printed_as_plain_text_is_not_treated_as_a_call():
    # the failure mode reported for some local models: raw tool JSON in the content
    text = '{"name": "send_email", "arguments": {"to": "a@b.c", "body": "x"}}'
    sb = Sandbox(seed=1)
    assert agent(FakeHTTP([final(text)])).run("x", sb) == text
    assert sb.calls == []


def test_exhausting_turns_raises_timeout():
    with pytest.raises(AgentTimeout):
        agent(FakeHTTP([calling()]), max_turns=2).run("loop", Sandbox(seed=1))


def test_server_errors_are_counted_by_the_runner():
    res = run_suite(lambda s: agent(FakeHTTP([final("x")], fail=True)), load_attacks(), TASKS, 2)
    assert all(p["errors"] == 2 for p in res["pairs"])


def test_factory_needs_only_a_model_and_defaults_the_url():
    with pytest.raises(SystemExit):
        make_agent_factory("ollama")
    a = make_agent_factory("ollama", "m")(0)
    assert a.base_url == "http://localhost:11434" and a.model == "m"
    assert make_agent_factory("ollama", "m", None, "http://other:11434/")(0).base_url == "http://other:11434"