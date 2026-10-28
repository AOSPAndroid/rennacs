"""Synthetic advisory feed + real loopback banner -> indexed potential report.

The advisory ID, affected range and service are fixtures, not public findings.
Only the loopback HTTP server receives a connection; advisory transport is fake.
"""
import asyncio

from rennacs import scanner
from rennacs.app import create_app
from rennacs.catalog import BASE, Catalog
from rennacs.db import Index
from rennacs.sweep import sweep
from rennacs.vulns import check


def test_resumed_catalog_to_real_loopback_to_reports(tmp_path, monkeypatch):
    path = str(tmp_path / "catalog-loopback.db")
    advisory_id = "CVE-2099-40001"
    advisory = {"id": advisory_id, "title": "Synthetic fixture advisory",
        "severity": {"cvss": 8.0}, "affected": [
            {"vendor": "Apache Software Foundation", "product": "Apache HTTP Server",
             "ranges": [{"introduced": "2.4.0", "fixed": "2.4.52"}]},
            {"product": "Unrelated Fixture", "ranges": [{"fixed": "900.0"}]},
        ]}
    calls = []

    def fake_feed(url):
        calls.append(url)
        if url == BASE:
            return {"entries": [{"id": advisory_id}], "nextCursor": "opaque+/="}
        if url == BASE + "/" + advisory_id:
            return advisory
        assert url == BASE + "?cursor=opaque%2B%2F%3D"
        return {"entries": [], "nextCursor": None}

    catalog = Catalog(path)
    first = catalog.sync(max_pages=1, max_requests=1, rate=10000, fetcher=fake_feed)
    assert first["complete"] is False
    assert first["status"]["pending_catalog_details"] == 1
    catalog.close()
    catalog = Catalog(path)
    try:
        resumed = catalog.sync(max_pages=1, max_requests=2, rate=10000, fetcher=fake_feed)
        assert resumed["complete"] is True
        assert resumed["stored"] == 1
    finally:
        catalog.close()
    assert len(calls) == 3
    assert check("Apache httpd", "2.4.51") == []  # Not a handwritten-rule result.

    idx = Index(path)

    async def scenario():
        handlers = set()

        async def handle(reader, writer):
            task = asyncio.current_task()
            handlers.add(task)
            try:
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 1)
                writer.write(b"HTTP/1.0 200 OK\r\nServer: Apache/2.4.51\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                handlers.discard(task)

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setattr(scanner, "_PROBES", {port: b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n"})
        monkeypatch.setattr(scanner, "_TLS_PORTS", set())
        try:
            result = await sweep("127.0.0.1/32", str(port), rate=10, timeout=0.5,
                                 on_host=idx.upsert_host)
            assert result.services == 1
            service = idx.host("127.0.0.1")["services"][0]
            assert service["product"] == "Apache httpd"
            assert service["vulns"][0]["cve"] == advisory_id
            app = create_app(path)
            app.config["TESTING"] = True
            client = app.test_client()
            report = client.get("/api/findings").get_json()
            assert report["total"] == 1
            finding = report["matches"][0]
            assert finding["assessment"]["status"] == "potential"
            assert finding["assessment"]["exploit_tested"] is False
            assert finding["advisories"][0]["match_status"] == "affected"
            assert finding["advisories"][0]["fixed_versions"] == ["2.4.52"]
            assert len(finding["advisories"][0]["matched_affected"]) == 1
            assert report["catalog"]["atomic_snapshot"] is False
            assert client.get("/findings").status_code == 200
        finally:
            server.close()
            await server.wait_closed()
            if handlers:
                await asyncio.gather(*handlers)

    try:
        asyncio.run(scenario())
    finally:
        idx.close()
