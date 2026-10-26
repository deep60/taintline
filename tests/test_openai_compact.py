import json

import pytest

from tripwire.attacks import load_attacks
from tripwire.attacks.runner import run_suite
from tripwire.sandbox import Sandbox
from tripwire.targets import make_agent_factory
from tripwire.targets.openai_compat import OpenAICompatAgent, to_openai_tools
from tripwire.targets.own_agent import AgentTimeout
from tripwire.tasks import TASKS


def final(text):
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def calling(name="read_file", arguments='{"path": "notes/todo.txt"}', call_id="c1"):
    return {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
        {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}]}}]}


class FakeResponse:
    def __init__(self, data, fail=False):
        self._data, self._fail = data, fail

    def raise_for_status(self):
        if self._fail:
            raise RuntimeError("HTTP 429")

    def json(self):
        return self._data


class FakeHTTP:
    """Scripted stand-in for httpx.Client. The last scripted response repeats."""
    def __init__(self, responses, fail=False):
        self.responses, self.requests, self.fail = list(responses), [], fail

    def post(self, url, json=None, headers=None):
        self.requests.append({"url": url, "json": json, "headers": headers})
        data = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        return FakeResponse(data, self.fail)


def agent(http, **kw):
    return OpenAICompatAgent("m", "http://localhost:11434/v1/", client=http, **kw)


def test_returns_text_when_no_tool_calls():
    assert agent(FakeHTTP([final("done")])).run("hi", Sandbox(seed=1)) == "done"


def test_tool_loop_runs_tool_and_sends_result_back():
    http = FakeHTTP([calling(), final("milk and domain")])
    sb = Sandbox(seed=1)
    assert agent(http).run("list todos", sb) == "milk and domain"
    assert [c.name for c in sb.calls] == ["read_file"]
    second = http.requests[1]["json"]["messages"]
    assert second[-1]["role"] == "tool" and second[-1]["tool_call_id"] == "c1"
    assert "milk" in second[-1]["content"]


def test_url_is_normalised_and_system_prompt_is_first_message():
    http = FakeHTTP([final("ok")])
    agent(http, system="BE GULLIBLE").run("hi", Sandbox(seed=1))
    assert http.requests[0]["url"] == "http://localhost:11434/v1/chat/completions"
    assert http.requests[0]["json"]["messages"][0] == {"role": "system", "content": "BE GULLIBLE"}


def test_malformed_tool_arguments_do_not_crash_the_loop():
    http = FakeHTTP([calling(arguments="{not json"), final("sorry")])
    sb = Sandbox(seed=1)
    assert agent(http).run("x", sb) == "sorry"
    assert sb.calls[0].result.startswith("error")


def test_auth_header_only_when_the_key_exists(monkeypatch):
    http = FakeHTTP([final("a"), final("b")])
    monkeypatch.delenv("MY_KEY", raising=False)
    agent(http, api_key_env="MY_KEY").run("hi", Sandbox(seed=1))
    assert "Authorization" not in http.requests[0]["headers"]
    monkeypatch.setenv("MY_KEY", "sekret")
    agent(http, api_key_env="MY_KEY").run("hi", Sandbox(seed=1))
    assert http.requests[1]["headers"]["Authorization"] == "Bearer sekret"


def test_exhausting_turns_raises_timeout():
    with pytest.raises(AgentTimeout):
        agent(FakeHTTP([calling()]), max_turns=2).run("loop", Sandbox(seed=1))


def test_http_errors_are_counted_by_the_runner():
    res = run_suite(lambda s: agent(FakeHTTP([final("x")], fail=True)), load_attacks(), TASKS, 2)
    assert all(p["errors"] == 2 for p in res["pairs"])


def test_tool_definitions_are_converted_to_openai_format():
    tools = to_openai_tools(Sandbox(seed=1).tool_defs())
    assert tools[0]["type"] == "function"
    assert {"name", "description", "parameters"} <= set(tools[0]["function"])
    json.dumps(tools)


def test_factory_requires_model_and_base_url():
    with pytest.raises(SystemExit):
        make_agent_factory("openai-compat", "m")
    with pytest.raises(SystemExit):
        make_agent_factory("openai-compat", None, None, "http://x/v1")
    assert make_agent_factory("openai-compat", "m", None, "http://x/v1")(0).model == "m"