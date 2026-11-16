import httpx
import pytest

from dyepack.targets import make_agent_factory
from dyepack.targets.http_retry import ModelRequestFailed
from dyepack.targets.ollama import OllamaAgent
from dyepack.targets.openai_compat import OpenAICompatAgent

OK = {"choices": [{"message": {"role": "assistant", "content": "done"}}]}


class Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._data = status, data or OK

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(f"HTTP {self.status_code}", request=None, response=None)

    def json(self):
        return self._data


class Flaky:
    """Each script item is an exception to raise or a status code to return."""
    def __init__(self, script):
        self.script, self.calls = list(script), 0

    def post(self, url, json=None, headers=None):
        self.calls += 1
        item = self.script.pop(0) if self.script else 200
        if isinstance(item, Exception):
            raise item
        return Resp(item)


class SB:
    def tool_defs(self):
        return []


def agent(script, retries=2):
    return OpenAICompatAgent("m", "http://127.0.0.1:1234/v1", client=Flaky(script), max_retries=retries, backoff=0)


def test_a_stalled_request_is_retried_and_counted():
    a = agent([httpx.ReadTimeout("timed out"), 503])
    assert a.run("hi", SB()) == "done"
    assert a.retries == 2 and a._client.calls == 3


def test_retries_run_out_into_an_error_never_a_pass():
    a = agent([httpx.ReadTimeout("timed out")] * 5, retries=2)
    with pytest.raises(ModelRequestFailed, match="failed 3 time"):
        a.run("hi", SB())
    assert a.retries == 2


def test_a_bad_request_is_not_retried():
    a = agent([400])
    with pytest.raises(httpx.HTTPStatusError):
        a.run("hi", SB())
    assert a.retries == 0 and a._client.calls == 1


def test_connection_refused_is_retried():
    a = agent([httpx.ConnectError("refused")])
    assert a.run("hi", SB()) == "done" and a.retries == 1


def test_ollama_uses_the_same_retry():
    class OllamaFlaky(Flaky):
        def post(self, url, json=None, headers=None):
            r = super().post(url, json, headers)
            r._data = {"message": {"role": "assistant", "content": "done"}}
            return r
    o = OllamaAgent("m", client=OllamaFlaky([httpx.ReadTimeout("t")]), backoff=0)
    assert o.run("hi", SB()) == "done" and o.retries == 1


def test_factory_passes_timeout_and_retries():
    a = make_agent_factory("openai-compat", "m", base_url="http://x/v1", request_timeout=600, retries=5)(1)
    assert a.timeout == 600 and a.max_retries == 5
    assert make_agent_factory("openai-compat", "m", base_url="http://x/v1")(1).timeout == 120.0
