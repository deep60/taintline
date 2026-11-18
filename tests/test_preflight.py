import httpx
import pytest

from dyepack.cli import main
from dyepack.targets.http_retry import ModelRequestFailed, post_json
from dyepack.targets.preflight import EndpointUnavailable, check_endpoint


class Resp:
    def __init__(self, status=200, data=None, bad_json=False):
        self.status_code, self._data, self._bad = status, data, bad_json

    def json(self):
        if self._bad:
            raise ValueError("not json")
        return self._data


class Client:
    def __init__(self, result):
        self.result, self.urls, self.headers = result, [], []

    def get(self, url, headers=None):
        self.urls.append(url)
        self.headers.append(headers or {})
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def close(self):
        pass


LMS = Resp(data={"data": [{"id": "redsage-qwen3-8b-ins"}, {"id": "other"}]})


def test_openai_compat_lists_models_at_base_url():
    c = Client(LMS)
    assert check_endpoint("openai-compat", "redsage-qwen3-8b-ins", "http://localhost:1234/v1/", client=c) is None
    assert c.urls == ["http://localhost:1234/v1/models"]


def test_refused_connection_stops_with_a_hint():
    c = Client(httpx.ConnectError("[Errno 61] Connection refused"))
    with pytest.raises(EndpointUnavailable, match="Is the model server running"):
        check_endpoint("openai-compat", "m", "http://localhost:1234/v1", client=c)


def test_timeout_stops():
    with pytest.raises(EndpointUnavailable, match="did not answer"):
        check_endpoint("ollama", "m", None, client=Client(httpx.ReadTimeout("slow")))


def test_missing_model_names_what_is_offered():
    with pytest.raises(EndpointUnavailable, match="offers: redsage-qwen3-8b-ins, other"):
        check_endpoint("openai-compat", "typo", "http://h/v1", client=Client(LMS))


def test_running_server_with_no_model_loaded():
    with pytest.raises(EndpointUnavailable, match="offers no models"):
        check_endpoint("openai-compat", "m", "http://h/v1", client=Client(Resp(data={"data": []})))


def test_ollama_default_url_and_latest_tag():
    c = Client(Resp(data={"models": [{"name": "llama3.1:latest"}]}))
    assert check_endpoint("ollama", "llama3.1", None, client=c) is None
    assert c.urls == ["http://localhost:11434/api/tags"]
    with pytest.raises(EndpointUnavailable):
        check_endpoint("ollama", "llama3.1:70b", None, client=c)


def test_bad_key_is_an_error(monkeypatch):
    monkeypatch.setenv("TEST_KEY_VAR", "k")
    c = Client(Resp(401))
    with pytest.raises(EndpointUnavailable, match=r"\$TEST_KEY_VAR"):
        check_endpoint("openai-compat", "m", "http://h/v1", "TEST_KEY_VAR", client=c)
    assert c.headers[0]["Authorization"] == "Bearer k"


@pytest.mark.parametrize("resp", [Resp(404), Resp(data=None, bad_json=True)])
def test_server_without_a_model_list_warns_and_goes_ahead(resp):
    assert "going ahead" in check_endpoint("openai-compat", "m", "http://h/v1", client=Client(resp))


@pytest.mark.parametrize("kind", ["mock-naive", "mock-hardened", "anthropic"])
def test_other_agents_are_not_contacted(kind):
    c = Client(AssertionError("must not be called"))
    assert check_endpoint(kind, "m", None, client=c) is None and c.urls == []


def test_cli_stops_before_trial_one(tmp_path, monkeypatch):
    monkeypatch.setattr(httpx, "Client", lambda timeout: Client(httpx.ConnectError("refused")))
    sc = tmp_path / "s.yaml"
    sc.write_text("name: t\nauthorized_by: me\nservers: ['localhost:11434']\n")
    with pytest.raises(SystemExit) as e:
        main(["run", "--agent", "ollama", "--model", "x", "--scope", str(sc), "--out", str(tmp_path / "o")])
    assert "No trials were run" in str(e.value) and not (tmp_path / "o").exists()


def test_preflight_runs_only_after_the_scope_gate(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(httpx, "Client", lambda timeout: called.append(1))
    sc = tmp_path / "s.yaml"
    sc.write_text("name: t\nauthorized_by: me\nservers: ['localhost:11434']\n")
    with pytest.raises(SystemExit) as e:
        main(["run", "--agent", "openai-compat", "--model", "m", "--base-url", "http://evil.example/v1",
              "--scope", str(sc)])
    assert "refused" in str(e.value) and called == []


class Agent:
    timeout, max_retries, backoff, retries = 1.0, 0, 0.0, 0

    def __init__(self, exc):
        self.exc = exc

    def _http(self):
        exc = self.exc

        class H:
            def post(self, *a, **k):
                raise exc
        return H()


def test_retry_message_matches_the_failure():
    with pytest.raises(ModelRequestFailed, match="is the model server running"):
        post_json(Agent(httpx.ConnectError("refused")), "http://h", {})
    with pytest.raises(ModelRequestFailed, match="raise --request-timeout"):
        post_json(Agent(httpx.ReadTimeout("slow")), "http://h", {})
