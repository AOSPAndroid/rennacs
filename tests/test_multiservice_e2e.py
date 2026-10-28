"""Real loopback multi-service -> scan -> index -> findings -> refresh test.

Banners are SYNTHETIC protocol fixtures, not discoveries about Internet hosts.
No exploit or live third-party service is involved.
"""
import asyncio
import json

from rennacs import scanner
from rennacs.app import create_app
from rennacs.db import Index
from rennacs.sweep import sweep


def test_real_loopback_multiservice_pipeline_and_partial_refresh(tmp_path, monkeypatch):
    path = str(tmp_path / "loopback.db")
    idx = Index(path)

    async def scenario():
        servers, handlers, errors = [], set(), []
        definitions = [
            ("http", b"HTTP/1.0 200 OK\r\nServer: Apache/2.4.49\r\nContent-Length: 0\r\n\r\n", True),
            ("ssh", b"SSH-2.0-OpenSSH_9.2p1\r\n", False),
            ("smtp", b"220 fixture.local ESMTP Exim 4.90\r\n", False),
            ("database", b"redis_version:6.0.20\r\n", False),
        ]
        endpoints = {}

        def handler_for(banner, needs_request):
            async def handle(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                try:
                    if needs_request:
                        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 1)
                    writer.write(banner)
                    await asyncio.wait_for(writer.drain(), 1)
                except Exception as exc:
                    errors.append(repr(exc))
                finally:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), 1)
                    handlers.discard(task)
            return handle

        try:
            for label, banner, needs_request in definitions:
                server = await asyncio.start_server(handler_for(banner, needs_request), "127.0.0.1", 0)
                servers.append(server)
                endpoints[label] = server.sockets[0].getsockname()[1]
            monkeypatch.setattr(scanner, "_PROBES", {
                endpoints["http"]: b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n",
            })
            # Ephemeral fixture ports must not inherit a production TLS-port label.
            monkeypatch.setattr(scanner, "_TLS_PORTS", set())
            port_spec = ",".join(str(port) for port in endpoints.values())
            stats = await sweep("127.0.0.1/32", port_spec, rate=50, timeout=0.5,
                                on_host=idx.upsert_host)
            assert stats.services == 4
            stored = idx.host("127.0.0.1")
            assert {s["product"] for s in stored["services"]} == {
                "Apache httpd", "OpenSSH", "Exim", "Redis",
            }
            app = create_app(path)
            app.config["TESTING"] = True
            client = app.test_client()
            findings = client.get("/api/findings?q=ip:127.0.0.1").get_json()
            assert findings["total"] == findings["count"] == 3
            assert all(f["assessment"]["status"] == "potential" for f in findings["matches"])
            assert client.get("/findings?q=ip:127.0.0.1").status_code == 200

            # Remove one local fixture, then rescan ONLY that port. Other observed
            # service families must survive, while loss remains explicitly uncertain.
            servers[0].close()
            await servers[0].wait_closed()
            await sweep("127.0.0.1/32", str(endpoints["http"]), rate=50, timeout=0.5,
                        on_host=idx.upsert_host)
            current = idx.host("127.0.0.1")
            assert {s["product"] for s in current["services"]} == {"OpenSSH", "Exim", "Redis"}
            history = client.get("/api/host/127.0.0.1/history").get_json()
            assert history["events"][0]["state"] == "not_observed"
            assert "not proof" in history["events"][0]["note"]
            remaining = client.get("/api/findings?q=ip:127.0.0.1").get_json()
            assert remaining["total"] == 2
            assert not errors, errors
            evidence = {
                "fixture_only": True, "destination": "127.0.0.1",
                "observed_services": stats.services,
                "fingerprints": sorted(s["product"] for s in stored["services"]),
                "potential_service_assessments": findings["total"],
                "services_preserved_after_partial_refresh": len(current["services"]),
                "missing_service_state": history["events"][0]["state"],
            }
            (tmp_path / "fixture-evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            print(json.dumps(evidence))
        finally:
            for server in servers:
                server.close()
                await server.wait_closed()
            if handlers:
                await asyncio.gather(*handlers)

    try:
        asyncio.run(scenario())
    finally:
        idx.close()
