"""HTTP transport for depaudit.

This is the **single chokepoint** for all network I/O in the project. Feature code
(e.g. :mod:`depaudit.osv`) must go through :func:`request_json` rather than importing
``urllib``/``requests`` directly, so that timeouts, retries, and scheme validation are
applied uniformly. Only stdlib is used — the tool keeps its own attack surface minimal.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from depaudit import __version__

DEFAULT_TIMEOUT = 20.0
"""Seconds to wait for each request. Never rely on library defaults (may be infinite)."""

DEFAULT_RETRIES = 2
"""Number of *additional* attempts after the first on transient failures."""

_USER_AGENT = f"depaudit/{__version__}"
_BACKOFF_SECONDS = 0.5


class NetworkError(RuntimeError):
    """Raised when a request cannot be completed (after retries) or returns bad JSON."""


def request_json(
    url: str,
    *,
    method: str = "GET",
    payload: Any = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> Any:
    """Perform one JSON-over-HTTPS request and return the parsed response body.

    Args:
        url: Absolute ``https://`` URL. Non-HTTPS schemes are rejected outright.
        method: HTTP method, e.g. ``"GET"`` or ``"POST"``.
        payload: If given, JSON-encoded and sent as the request body with a
            ``Content-Type: application/json`` header.
        timeout: Per-attempt timeout in seconds (always passed explicitly).
        retries: Additional attempts after the first on transient failures
            (connection errors, timeouts, HTTP 5xx). ``0`` disables retrying and
            the inter-attempt sleep.

    Returns:
        The decoded JSON value (typically a ``dict`` or ``list``).

    Raises:
        NetworkError: On an invalid scheme, exhausted retries, a non-transient HTTP
            error, or a response body that is not valid JSON.
    """
    if urlsplit(url).scheme != "https":
        raise NetworkError(f"refusing non-https URL: {url!r}")

    data = None
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    # S310: scheme is validated as https above; url is built from a trusted constant
    # base in feature code, never from untrusted input.
    request = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310

    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            # nosec/noqa: scheme is validated as https above; url is built from a
            # trusted constant base in feature code, not from untrusted input.
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                raw = response.read()
            break
        except urllib.error.HTTPError as exc:
            # Retry only server-side (5xx) errors; 4xx are terminal.
            last_error = exc
            if exc.code < 500 or attempt == retries:
                raise NetworkError(f"HTTP {exc.code} from {url}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt == retries:
                raise NetworkError(f"request to {url} failed: {exc}") from exc
        if retries:
            time.sleep(_BACKOFF_SECONDS * (attempt + 1))
    else:  # pragma: no cover - loop always breaks or raises
        raise NetworkError(f"request to {url} failed: {last_error}")

    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NetworkError(f"invalid JSON from {url}: {exc}") from exc
