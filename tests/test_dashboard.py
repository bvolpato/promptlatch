import sqlite3
import threading
import time
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

import httpx
import pytest
from fastapi import FastAPI

from promptlatch.dashboard import create_dashboard_app, dashboard_shell
from promptlatch.history import HistoryReader, HistoryStore

_AUTH = {"Authorization": "Bearer dashboard-test-token"}
_SESSION_COOKIE = "promptlatch_dashboard_session"
_SESSION_SECONDS = 30 * 24 * 60 * 60


def session_cookie(response: httpx.Response) -> str:
    return response.cookies[_SESSION_COOKIE]


@pytest.fixture
def database(tmp_path: Path) -> Path:
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    for index in range(2):
        request_id = f"request-{index}"
        assert store.submit_start(
            {
                "request_id": request_id,
                "thread_id": "thread-a",
                "thread_source": "inferred",
                "started_at": time.time() - index,
                "method": "POST",
                "path": "/v1/chat/completions",
                "model": "<script>alert('model')</script>",
                "provider": "openai",
                "request_body": '{"content":"<img src=x onerror=alert(1)> [REDACTED_SECRET]"}',
                "session_preview": f"session context {index}",
                "user_preview": f"user context {index}",
                "assistant_preview": f"prior answer {index}",
                "redactions": 1,
                "rule_hits": {"assigned_secret": 1},
            }
        )
        assert store.submit_finish(
            request_id,
            {
                "outcome": "success",
                "completed_at": time.time(),
                "status_code": 200,
                "input_tokens": 10,
                "output_tokens": 5,
                "total_tokens": 15,
            },
        )
    store.close()
    return path


@pytest.mark.asyncio
async def test_dashboard_auth_and_static_shell(tmp_path: Path) -> None:
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost:8001"
    ) as client:
        for endpoint in (
            "/api/summary",
            "/api/threads",
            "/api/requests",
            "/api/requests/test",
            "/api/requests/test/location",
            "/api/threads/test/requests",
        ):
            for headers in ({}, {"Authorization": "Bearer proxy-token"}):
                response = await client.get(endpoint, headers=headers)
                assert response.status_code == 401
                assert response.headers["www-authenticate"] == "Bearer"
                assert response.headers["cache-control"] == "no-store"
        for endpoint, media_type in (
            ("/", "text/html"),
            ("/assets/app.js", "text/javascript"),
            ("/assets/style.css", "text/css"),
            ("/assets/favicon.svg", "image/svg+xml"),
        ):
            response = await client.get(endpoint)
            assert response.status_code == 200
            assert response.headers["content-type"].startswith(media_type)
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["x-frame-options"] == "DENY"
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
            assert "unsafe-inline" not in response.headers["content-security-policy"]
            assert "access-control-allow-origin" not in response.headers
        assert (await client.get("/assets/history.sqlite3")).status_code == 404
        assert (await client.post("/api/requests", headers=_AUTH)).status_code == 405


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "attacker.example"},
        {"Host": "localhost.attacker.example"},
        {"Host": "127.0.0.1.attacker.example"},
        {"Host": "192.168.1.1"},
        {"Host": "localhost:65536"},
        {"Host": "localhost:0"},
        {"Origin": "https://attacker.example"},
        {"Origin": "null"},
        {"Origin": "http://localhost:8002"},
        {"Origin": "https://localhost:8001"},
        {"Origin": "http://127.0.0.1:8001"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
    ],
)
async def test_dashboard_rejects_foreign_browser_origins(tmp_path: Path, headers: dict) -> None:
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost:8001"
    ) as client:
        response = await client.get("/api/summary", headers={**_AUTH, **headers})
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "127.0.0.2", "[::1]"])
async def test_dashboard_accepts_local_same_origin(tmp_path: Path, host: str) -> None:
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    origin = f"http://{host}:8001"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=origin) as client:
        response = await client.get(
            "/api/summary", headers={**_AUTH, "Origin": origin, "Sec-Fetch-Site": "same-origin"}
        )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_dashboard_missing_history_is_read_only(tmp_path: Path) -> None:
    path = tmp_path / "not-created" / "history.sqlite3"
    app = create_dashboard_app(path, "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=_AUTH
    ) as client:
        summary = (await client.get("/api/summary")).json()
        assert summary["totals"]["requests"] == 0
        assert summary["totals"]["cost_usd"] is None
        for endpoint in ("/api/threads", "/api/requests", "/api/threads/missing/requests"):
            response = await client.get(endpoint)
            assert response.status_code == 200
            assert response.json()["items"] == []
            assert response.json()["total"] == 0
        assert (await client.get("/api/requests/missing")).status_code == 404
    assert not path.parent.exists()


@pytest.mark.asyncio
async def test_dashboard_history_routes_and_pagination(database: Path) -> None:
    app = create_dashboard_app(database, "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=_AUTH
    ) as client:
        summary = (await client.get("/api/summary?days=7")).json()
        assert summary["totals"]["requests"] == 2
        assert summary["totals"]["total_tokens"] == 30
        assert summary["totals"]["rule_hits"] == {"assigned_secret": 2}
        assert summary["totals"]["unknown_cost_requests"] == 2
        threads = (await client.get("/api/threads")).json()
        assert threads["total"] == 1
        assert threads["items"][0]["thread_id"] == "thread-a"
        assert threads["items"][0]["session_preview"] == "session context 1"
        assert threads["items"][0]["latest_model"] == "<script>alert('model')</script>"
        assert threads["items"][0]["latest_provider"] == "openai"
        assert threads["items"][0]["latest_outcome"] == "success"
        assert threads["items"][0]["duration_ms"] >= 0
        assert threads["items"][0]["total_tokens"] == 30
        assert threads["items"][0]["cost_usd"] is None
        assert threads["items"][0]["known_cost_requests"] == 0
        assert threads["items"][0]["last_user_preview"] == "user context 0"
        assert threads["items"][0]["last_assistant_preview"] == "prior answer 0"
        first = (await client.get("/api/requests?thread_id=thread-a&limit=1")).json()
        second = (await client.get("/api/requests?thread_id=thread-a&limit=1&offset=1")).json()
        assert first["total"] == 2
        assert len(first["items"]) == 1
        assert first["items"][0]["request_id"] != second["items"][0]["request_id"]
        assert "request_body" not in first["items"][0]
        assert first["items"][0]["session_preview"] == "session context 0"
        assert first["items"][0]["user_preview"] == "user context 0"
        assert first["items"][0]["assistant_preview"] == "prior answer 0"
        assert (await client.get("/api/requests?thread_id=unknown")).json()["items"] == []
        detail = await client.get("/api/requests/request-0")
        assert detail.headers["content-type"] == "application/json"
        assert detail.headers["x-content-type-options"] == "nosniff"
        assert detail.json()["request_body"].startswith('{"content":"<img')
        assert detail.json()["redactions"] == 1
        for query in ("limit=0", "limit=101", "offset=-1"):
            assert (await client.get(f"/api/requests?{query}")).status_code == 422
        assert (await client.get("/api/summary?days=0")).status_code == 422


@pytest.mark.asyncio
async def test_dashboard_thread_tree_pagination_privacy_and_limits(database: Path) -> None:
    app = create_dashboard_app(database, "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=_AUTH
    ) as client:
        first = (await client.get("/api/threads/thread-a/requests?limit=1")).json()
        second = (await client.get("/api/threads/thread-a/requests?limit=1&offset=1")).json()
        assert first["total"] == second["total"] == 2
        assert first["items"][0]["request_id"] == "request-1"
        assert second["items"][0]["request_id"] == "request-0"
        assert first["items"][0]["ordinal"] == 1
        assert second["items"][0]["ordinal"] == 2
        assert first["items"][0]["parent_request_id"] is None
        assert all("request_body" not in item for item in first["items"] + second["items"])
        assert first["items"][0]["session_preview"] == "session context 1"
        assert first["items"][0]["user_preview"] == "user context 1"
        assert first["items"][0]["assistant_preview"] == "prior answer 1"
        assert "<img" not in str(first)
        newest_first = (
            await client.get("/api/threads/thread-a/requests?order=desc&limit=1")
        ).json()
        assert newest_first["items"][0]["request_id"] == "request-0"
        assert newest_first["items"][0]["ordinal"] == 2
        newest_page = (
            await client.get("/api/threads/thread-a/requests?order=desc&limit=1&offset=1")
        ).json()
        assert newest_page["items"][0]["request_id"] == "request-1"
        assert newest_page["items"][0]["ordinal"] == 1
        assert newest_page["items"][0]["parent_request_id"] is None
        assert (await client.get("/api/threads/missing/requests")).json()["items"] == []
        for query in ("limit=0", "limit=101", "offset=-1", "order=sideways"):
            assert (await client.get(f"/api/threads/thread-a/requests?{query}")).status_code == 422
        assert (await client.get(f"/api/threads/{'a' * 257}/requests")).status_code == 422


@pytest.mark.asyncio
async def test_inference_scope_hides_ancillary_calls_and_preserves_their_links(
    database: Path,
) -> None:
    store = HistoryStore(database)
    store.start()
    for request_id, thread_id in (("poll-in-session", "thread-a"), ("poll-only", "poll-session")):
        store.submit_start(
            {
                "request_id": request_id,
                "thread_id": thread_id,
                "started_at": time.time() + 10,
                "method": "GET",
                "path": "/other",
                "usage_applicable": False,
            }
        )
        store.submit_finish(request_id, {"outcome": "success", "completed_at": time.time()})
    store.close()
    app = create_dashboard_app(database, "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=_AUTH
    ) as client:
        assert (await client.get("/api/threads")).json()["total"] == 2
        filtered = (await client.get("/api/threads?traffic=inference")).json()
        assert filtered["total"] == 1
        assert filtered["items"][0]["requests"] == 2
        assert filtered["items"][0]["latest_model"] == "<script>alert('model')</script>"
        calls = (await client.get("/api/requests?traffic=inference")).json()
        assert calls["total"] == 2
        assert all(item["method"] == "POST" for item in calls["items"])
        history = (
            await client.get("/api/threads/thread-a/requests?traffic=inference&order=desc")
        ).json()
        assert history["total"] == 2
        assert [item["ordinal"] for item in history["items"]] == [2, 1]
        location = (await client.get("/api/requests/poll-only/location?traffic=inference")).json()
        assert location["traffic"] == "all"
        assert location["thread"]["thread_id"] == "poll-session"
        assert "request_body" not in location["thread"]
        assert (await client.get("/api/requests/poll-only")).status_code == 200
        for endpoint in (
            "/api/threads",
            "/api/requests",
            "/api/threads/thread-a/requests",
            "/api/requests/poll-only/location",
        ):
            assert (await client.get(endpoint + "?traffic=invalid")).status_code == 422


@pytest.mark.asyncio
async def test_request_location_finds_older_pages_with_timestamp_ties(tmp_path: Path) -> None:
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    for index in range(105):
        store.submit_start(
            {
                "request_id": f"old-{index:03d}",
                "thread_id": "old-session",
                "started_at": 100,
                "request_body": '{"content":"body must stay out of location"}',
                "user_preview": "retained preview",
            }
        )
        store.submit_finish(f"old-{index:03d}", {"outcome": "success", "completed_at": 101})
    for index in range(52):
        store.submit_start(
            {
                "request_id": f"new-{index:03d}",
                "thread_id": f"new-session-{index:03d}",
                "started_at": 200,
                "request_body": "other body must stay out of location",
            }
        )
        store.submit_finish(f"new-{index:03d}", {"outcome": "success", "completed_at": 201})
    store.close()
    app = create_dashboard_app(path, "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=_AUTH
    ) as client:
        location = (await client.get("/api/requests/old-000/location")).json()
        assert location["thread_offset"] == 50
        assert location["request_offset"] == 100
        assert location["thread"]["thread_id"] == "old-session"
        assert location["thread"]["requests"] == 105
        assert "request_body" not in location["thread"]
        assert "body must stay out" not in str(location)
        sessions = (await client.get("/api/threads?offset=50")).json()["items"]
        assert location["thread"] == next(
            item for item in sessions if item["thread_id"] == "old-session"
        )
        requests = (
            await client.get("/api/threads/old-session/requests?offset=100&order=desc")
        ).json()["items"]
        assert requests[-1]["request_id"] == "old-000"
        assert requests[-1]["ordinal"] == 1
        newest = (await client.get("/api/requests/old-104/location")).json()
        assert newest["request_offset"] == 0
        tied = (await client.get("/api/requests/new-001/location")).json()
        assert tied["thread_offset"] == 50
        assert (await client.get("/api/requests/absent/location")).status_code == 404
        assert (await client.get(f"/api/requests/{'a' * 257}/location")).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [sqlite3.DatabaseError, PermissionError])
async def test_dashboard_reads_off_event_loop_and_hides_database_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]
) -> None:
    main_thread = threading.get_ident()
    read_threads = []

    def broken_summary(self: HistoryReader, days: int) -> dict:
        read_threads.append(threading.get_ident())
        raise error_type("sensitive data must not reach response")

    monkeypatch.setattr(HistoryReader, "summary", broken_summary)
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=_AUTH
    ) as client:
        response = await client.get("/api/summary")
    assert response.status_code == 503
    assert response.json() == {"detail": "History is temporarily unavailable"}
    assert response.headers["cache-control"] == "no-store"
    assert read_threads and all(thread != main_thread for thread in read_threads)


def test_dashboard_requires_independent_token(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="dashboard token is required"):
        create_dashboard_app(tmp_path / "history.sqlite3", "")


@pytest.mark.asyncio
async def test_dashboard_mount_resolves_assets_and_protects_network_api(database: Path) -> None:
    class Resources(HTMLParser):
        base: str = ""

        def __init__(self) -> None:
            super().__init__()
            self.assets: list[str] = []

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            attributes = dict(attrs)
            if tag == "base":
                self.base = attributes.get("href") or ""
            if tag in {"script", "link"}:
                self.assets.append(attributes.get("src") or attributes.get("href") or "")

    parent = FastAPI()
    parent.get("/")(lambda: dashboard_shell("/_promptlatch"))
    parent.mount(
        "/_promptlatch",
        create_dashboard_app(
            database, "dashboard-test-token", url_prefix="/_promptlatch", loopback_only=False
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=parent), base_url="http://proxy.example:8000"
    ) as client:
        root = await client.get("/")
        assert root.status_code == 200
        assert root.headers["cache-control"] == "no-store"
        assert "base-uri 'self'" in root.headers["content-security-policy"]
        resources = Resources()
        resources.feed(root.text)
        base = urljoin(str(root.url), resources.base)
        assert base == "http://proxy.example:8000/_promptlatch/"
        assert resources.assets
        for path in resources.assets:
            assert (await client.get(urljoin(base, path))).status_code == 200
        summary_url = urljoin(base, "api/summary")
        assert (await client.get(summary_url)).status_code == 401
        response = await client.get(
            summary_url, headers={**_AUTH, "Origin": "http://proxy.example:8000"}
        )
        assert response.status_code == 200
        assert response.json()["totals"]["requests"] == 2
        assert (await client.get("/api/summary", headers=_AUTH)).status_code == 404
        for headers in (
            {"Origin": "http://attacker.example"},
            {"Host": "bad..host"},
            {"Host": "proxy.example:65536"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            assert (await client.get(summary_url, headers={**_AUTH, **headers})).status_code == 403


def test_dashboard_shell_rejects_external_base_url() -> None:
    with pytest.raises(ValueError, match="absolute path"):
        dashboard_shell("//attacker.example")


@pytest.mark.asyncio
async def test_dashboard_browser_session_expires_without_renewal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [time.time()]
    monkeypatch.setattr("promptlatch.dashboard.time.time", lambda: clock[0])
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        login = await client.post("/api/session", headers=_AUTH)
        assert login.status_code == 200
        expires = int(clock[0]) + _SESSION_SECONDS
        assert login.json() == {"expires_at": expires}
        cookie = session_cookie(login)
        assert "dashboard-test-token" not in cookie
        cookie_header = {"Cookie": f"{_SESSION_COOKIE}={cookie}"}
        assert (await client.get("/api/session", headers=cookie_header)).json() == {
            "expires_at": expires
        }
        assert (await client.get("/api/summary", headers=cookie_header)).status_code == 200
        assert (await client.post("/api/session", headers=cookie_header)).status_code == 401
        clock[0] = expires - 0.001
        for endpoint in ("/api/session", "/api/summary", "/api/requests"):
            response = await client.get(endpoint, headers=cookie_header)
            assert response.status_code == 200
            assert "set-cookie" not in response.headers
        clock[0] = expires
        for endpoint in ("/api/session", "/api/summary", "/api/threads"):
            response = await client.get(endpoint, headers=cookie_header)
            assert response.status_code == 401
            assert response.headers["cache-control"] == "no-store"
        login_again = await client.post("/api/session", headers={**cookie_header, **_AUTH})
        assert login_again.status_code == 200
        assert login_again.json()["expires_at"] == expires + _SESSION_SECONDS
        assert session_cookie(login_again) != cookie


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("prefix", ["", "/_promptlatch"])
async def test_dashboard_session_cookie_flags_and_mount_scope(
    tmp_path: Path, scheme: str, prefix: str
) -> None:
    dashboard = create_dashboard_app(
        tmp_path / "missing.sqlite3", "dashboard-test-token", url_prefix=prefix
    )
    if prefix:
        app = FastAPI()
        app.mount(prefix, dashboard)
    else:
        app = dashboard
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"{scheme}://localhost"
    ) as client:
        response = await client.post(f"{prefix}/api/session", headers=_AUTH)
        assert response.status_code == 200
        header = response.headers["set-cookie"]
        assert "HttpOnly" in header
        assert "SameSite=strict" in header
        assert f"Path={prefix}/" in header
        assert f"Max-Age={_SESSION_SECONDS}" in header
        expires = datetime.fromtimestamp(response.json()["expires_at"], UTC)
        assert f"expires={expires.strftime('%a, %d %b %Y %H:%M:%S GMT')}" in header
        assert ("Secure" in header) == (scheme == "https")
        assert (await client.get(f"{prefix}/api/session")).status_code == 200
        logout = await client.delete(f"{prefix}/api/session")
        assert logout.status_code == 200
        assert "Max-Age=0" in logout.headers["set-cookie"]
        assert f"Path={prefix}/" in logout.headers["set-cookie"]
        assert "HttpOnly" in logout.headers["set-cookie"]
        assert "SameSite=strict" in logout.headers["set-cookie"]
        assert ("Secure" in logout.headers["set-cookie"]) == (scheme == "https")
        assert (await client.get(f"{prefix}/api/session")).status_code == 401


@pytest.mark.asyncio
async def test_dashboard_session_survives_restart_and_is_key_and_mount_bound(
    tmp_path: Path,
) -> None:
    path = tmp_path / "missing.sqlite3"
    first_app = create_dashboard_app(path, "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=first_app), base_url="http://localhost"
    ) as client:
        login = await client.post("/api/session", headers=_AUTH)
        cookie = session_cookie(login)
    for token, prefix, expected_status in (
        ("dashboard-test-token", "", 200),
        ("rotated-dashboard-token", "", 401),
        ("dashboard-test-token", "/_promptlatch", 401),
    ):
        app = create_dashboard_app(path, token, url_prefix=prefix)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://localhost"
        ) as client:
            response = await client.get(
                "/api/session", headers={"Cookie": f"{_SESSION_COOKIE}={cookie}"}
            )
        assert response.status_code == expected_status
        if expected_status == 200:
            assert response.json() == login.json()


@pytest.mark.asyncio
async def test_dashboard_session_rejects_tampering_and_future_issue_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [time.time()]
    monkeypatch.setattr("promptlatch.dashboard.time.time", lambda: clock[0])
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        login = await client.post("/api/session", headers=_AUTH)
        cookie = session_cookie(login)
        components = cookie.split(".")
        changed_expiry = components.copy()
        changed_expiry[2] = str(int(changed_expiry[2]) + _SESSION_SECONDS)
        changed_nonce = components.copy()
        changed_nonce[3] = ("x" if changed_nonce[3][0] != "x" else "y") + changed_nonce[3][1:]
        changed_signature = cookie[:-1] + ("0" if cookie[-1] != "0" else "1")
        for invalid in (
            "",
            "not-a-session",
            "x" * 4096,
            ".".join(changed_expiry),
            ".".join(changed_nonce),
            changed_signature,
        ):
            response = await client.get(
                "/api/session", headers={"Cookie": f"{_SESSION_COOKIE}={invalid}"}
            )
            assert response.status_code == 401
        clock[0] = int(components[1]) - 1
        response = await client.get(
            "/api/session", headers={"Cookie": f"{_SESSION_COOKIE}={cookie}"}
        )
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_session_rejects_ambiguous_credentials(tmp_path: Path) -> None:
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        login = await client.post("/api/session", headers=_AUTH)
        cookie_header = f"{_SESSION_COOKIE}={session_cookie(login)}"
        ambiguous_headers = (
            [("Authorization", _AUTH["Authorization"]), ("Authorization", _AUTH["Authorization"])],
            [("Cookie", cookie_header), ("Cookie", cookie_header)],
            [("Cookie", f"{cookie_header}; {cookie_header}")],
            [("Cookie", f"other=value; {cookie_header}; malformed")],
            [("Cookie", cookie_header), ("Authorization", "Bearer wrong-token")],
        )
        for headers in ambiguous_headers:
            assert (await client.get("/api/session", headers=headers)).status_code == 401
            assert (await client.get("/api/summary", headers=headers)).status_code == 401
        for headers in ambiguous_headers[:1]:
            assert (
                await client.post("/api/session", headers=[*headers, *_AUTH.items()])
            ).status_code == 401
        assert (
            await client.get("/api/session", headers={"Cookie": f"other=value; {cookie_header}"})
        ).status_code == 200


@pytest.mark.asyncio
async def test_dashboard_bootstrap_requires_header_and_preserves_manual_bearer(
    tmp_path: Path,
) -> None:
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        for headers in ({}, {"Authorization": "Bearer wrong-token"}, {"Authorization": "Basic x"}):
            response = await client.post("/api/session", headers=headers)
            assert response.status_code == 401
            assert "set-cookie" not in response.headers
        assert (
            await client.post("/api/session", json={"token": "dashboard-test-token"})
        ).status_code == 401
        assert (await client.post("/api/session?token=dashboard-test-token")).status_code == 401
        status = await client.get("/api/session", headers=_AUTH)
        assert status.json() == {"expires_at": None}
        assert "set-cookie" not in status.headers
        assert (await client.get("/api/summary", headers=_AUTH)).status_code == 200


@pytest.mark.asyncio
async def test_bootstrap_repairs_legacy_root_cookie_collision(tmp_path: Path) -> None:
    parent = FastAPI()
    parent.mount(
        "/_promptlatch",
        create_dashboard_app(
            tmp_path / "missing.sqlite3", "dashboard-test-token", url_prefix="/_promptlatch"
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=parent), base_url="http://localhost"
    ) as client:
        client.cookies.set(_SESSION_COOKIE, "legacy-cookie", domain="localhost.local", path="/")
        client.cookies.set(
            _SESSION_COOKIE, "stale-cookie", domain="localhost.local", path="/_promptlatch/"
        )
        assert (await client.get("/_promptlatch/api/session")).status_code == 401
        assert (await client.post("/_promptlatch/api/session")).status_code == 401
        login = await client.post("/_promptlatch/api/session", headers=_AUTH)
        assert login.status_code == 200
        assert len(client.cookies.jar) == 1
        assert (await client.get("/_promptlatch/api/session")).json() == login.json()
        restarted = FastAPI()
        restarted.mount(
            "/_promptlatch",
            create_dashboard_app(
                tmp_path / "missing.sqlite3", "dashboard-test-token", url_prefix="/_promptlatch"
            ),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=restarted),
            base_url="http://localhost",
            cookies=client.cookies,
        ) as reopened:
            assert (await reopened.get("/_promptlatch/api/session")).json() == login.json()


@pytest.mark.asyncio
async def test_dashboard_bootstrap_replaces_damaged_browser_cookie(tmp_path: Path) -> None:
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        client.cookies.set(_SESSION_COOKIE, "damaged-session", domain="localhost.local", path="/")
        assert (await client.get("/api/session")).status_code == 401
        assert (await client.post("/api/session")).status_code == 401
        login = await client.post("/api/session", headers=_AUTH)
        assert login.status_code == 200
        assert session_cookie(login) != "damaged-session"
        assert (await client.get("/api/session")).json() == login.json()
        assert (await client.get("/api/summary")).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["POST", "GET", "DELETE"])
async def test_dashboard_session_routes_reject_cross_origin(tmp_path: Path, method: str) -> None:
    app = create_dashboard_app(tmp_path / "missing.sqlite3", "dashboard-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        login = await client.post("/api/session", headers=_AUTH)
        assert login.status_code == 200
        response = await client.request(
            method, "/api/session", headers={**_AUTH, "Origin": "http://attacker.example"}
        )
        assert response.status_code == 403
        assert "set-cookie" not in response.headers
        assert (await client.get("/api/session")).status_code == 200
