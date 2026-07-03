"""Tests for the HTTP transport layer (depaudit.net)."""

import json
import urllib.error
from contextlib import contextmanager

import pytest

from depaudit import net


@contextmanager
def _fake_response(body):
    """A minimal stand-in for the urlopen context manager."""

    class _Resp:
        def read(self):
            return body

    yield _Resp()


def test_request_json_get_decodes_body(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["method"] = request.get_method()
        captured["timeout"] = timeout
        captured["url"] = request.full_url
        return _fake_response(b'{"ok": true}')

    monkeypatch.setattr(net.urllib.request, "urlopen", fake_urlopen)

    result = net.request_json("https://api.osv.dev/v1/vulns/X", timeout=7.5)

    assert result == {"ok": True}
    assert captured["method"] == "GET"
    assert captured["timeout"] == 7.5  # explicit timeout is forwarded, never defaulted


def test_request_json_post_sends_json_payload(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["method"] = request.get_method()
        captured["data"] = request.data
        captured["content_type"] = request.get_header("Content-type")
        return _fake_response(b'{"results": []}')

    monkeypatch.setattr(net.urllib.request, "urlopen", fake_urlopen)

    result = net.request_json(
        "https://api.osv.dev/v1/querybatch", method="POST", payload={"queries": []}
    )

    assert result == {"results": []}
    assert captured["method"] == "POST"
    assert json.loads(captured["data"]) == {"queries": []}
    assert captured["content_type"] == "application/json"


def test_request_json_rejects_non_https():
    with pytest.raises(net.NetworkError, match="non-https"):
        net.request_json("http://api.osv.dev/v1/vulns/X")


def test_request_json_retries_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def flaky_urlopen(request, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.URLError("temporary glitch")
        return _fake_response(b'{"ok": 1}')

    monkeypatch.setattr(net.urllib.request, "urlopen", flaky_urlopen)
    monkeypatch.setattr(net.time, "sleep", lambda _s: None)  # don't actually wait

    assert net.request_json("https://api.osv.dev/x", retries=2) == {"ok": 1}
    assert calls["n"] == 2


def test_request_json_raises_after_retries_exhausted(monkeypatch):
    def always_fails(request, timeout):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(net.urllib.request, "urlopen", always_fails)
    monkeypatch.setattr(net.time, "sleep", lambda _s: None)

    with pytest.raises(net.NetworkError, match="failed"):
        net.request_json("https://api.osv.dev/x", retries=2)


def test_request_json_4xx_is_terminal(monkeypatch):
    calls = {"n": 0}

    def not_found(request, timeout):
        calls["n"] += 1
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(net.urllib.request, "urlopen", not_found)

    with pytest.raises(net.NetworkError, match="HTTP 404"):
        net.request_json("https://api.osv.dev/x", retries=3)
    assert calls["n"] == 1  # 4xx is not retried


def test_request_json_malformed_body_raises(monkeypatch):
    def bad_json(request, timeout):
        return _fake_response(b"not json {{{")

    monkeypatch.setattr(net.urllib.request, "urlopen", bad_json)

    with pytest.raises(net.NetworkError, match="invalid JSON"):
        net.request_json("https://api.osv.dev/x")
