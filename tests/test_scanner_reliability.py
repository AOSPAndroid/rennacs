"""Scanner regressions; network fixtures are loopback-only."""

import asyncio
import socket
from unittest.mock import AsyncMock, Mock

import pytest

from rennacs import scanner
from rennacs.authz import NotAuthorized, Policy


def test_hostname_policy_validates_every_destination_before_any_scan(monkeypatch):
    async def scenario():
        resolver = AsyncMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
        ])
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)
        grab = AsyncMock(return_value=None)
        monkeypatch.setattr(scanner, "_grab", grab)
        with pytest.raises(NotAuthorized):
            await scanner.scan("127.0.0.2,mixed.example", "80", policy=Policy())
        grab.assert_not_awaited()

    asyncio.run(scenario())


def test_hostname_results_pin_addresses_and_retain_original_name(monkeypatch):
    async def scenario():
        resolver = AsyncMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
        ])
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)
        destinations = []

        async def grab(host, port, timeout):
            destinations.append(host)
            return scanner.ServiceResult(port=port)

        monkeypatch.setattr(scanner, "_grab", grab)
        results = await scanner.scan("lab.example", "80", policy=Policy())
        assert set(destinations) == {"127.0.0.1", "::1"}
        assert [result.ip for result in results] == ["127.0.0.1", "::1"]
        assert all(result.hostnames == ["lab.example"] for result in results)
        resolver.assert_awaited_once()

    asyncio.run(scenario())


@pytest.fixture
def loopback_tls_context(tmp_path):
    import ipaddress
    import ssl
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Rennacs Test CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "rennacs.local"),
    ])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("lab.example"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def test_real_tls_der_metadata_is_observed_not_trusted(
        monkeypatch, loopback_tls_context):
    async def scenario():
        requests, server_names = [], []
        done = asyncio.Event()
        loopback_tls_context.set_servername_callback(
            lambda sslobj, name, ctx: server_names.append(name))

        async def serve(reader, writer):
            try:
                requests.append(await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 1))
                writer.write(b"HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n\r\nlocal")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                done.set()

        server = await asyncio.start_server(serve, "127.0.0.1", 0,
                                            ssl=loopback_tls_context)
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setattr(scanner, "_TLS_PORTS", {port})
        monkeypatch.setattr(scanner, "_PROBES", {
            port: b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n"})
        resolver = AsyncMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))])
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)
        async with server:
            results = await scanner.scan("lab.example", str(port), timeout=0.5)
            await asyncio.wait_for(done.wait(), 1)
        svc = results[0].services[0]
        assert svc.ssl_cn == "rennacs.local"
        assert svc.ssl_issuer == "Rennacs Test CA"
        assert svc.ssl_sans == ["lab.example", "127.0.0.1"]
        assert svc.ssl_trust == "unverified"
        assert svc.has_ssl is True
        assert svc.product == "nginx"
        assert results[0].ip == "127.0.0.1"
        assert results[0].hostnames == ["lab.example"]
        assert server_names == ["lab.example"]
        assert b"Host: lab.example\r\n" in requests[0]
        resolver.assert_awaited_once()

    asyncio.run(scenario())


def test_all_host_callbacks_include_scanned_ports_but_return_only_live(monkeypatch):
    assert scanner.HostResult(ip="127.0.0.1").scanned_ports is None

    async def grab(host, port, timeout):
        if host == "127.0.0.1" and port == 80:
            return scanner.ServiceResult(port=port)
        return None  # no observation; this does not establish that a port is closed

    monkeypatch.setattr(scanner, "_grab", grab)
    seen = []
    results = asyncio.run(scanner.scan(
        "127.0.0.1,127.0.0.2", "443,80", on_host=seen.append))
    assert [result.ip for result in results] == ["127.0.0.1"]
    assert {result.ip for result in seen} == {"127.0.0.1", "127.0.0.2"}
    assert all(result.scanned_ports == [80, 443] for result in seen)
    assert next(result for result in seen if result.ip == "127.0.0.2").services == []


@pytest.mark.parametrize("concurrency", [7, 65535])
def test_all_tcp_ports_use_a_bounded_worker_pool(monkeypatch, concurrency):
    async def scenario():
        seen, samples = [], []
        active = peak = 0
        baseline_tasks = len(asyncio.all_tasks())

        async def grab(host, port, timeout):
            nonlocal active, peak
            if not samples:
                samples.append(len(asyncio.all_tasks()) - baseline_tasks)
            seen.append(port)
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0)
            active -= 1
            return scanner.ServiceResult(port=port) if port in {1, 65535} else None

        monkeypatch.setattr(scanner, "_grab", grab)
        ports = list(range(1, 65536))
        result = await scanner.scan_host("127.0.0.1", ports, concurrency=concurrency)
        assert samples[0] <= min(concurrency, 200) + 1, "port tasks must stay bounded"
        assert peak <= min(concurrency, 200)
        assert sorted(seen) == ports
        assert result.scanned_ports == ports
        assert [svc.port for svc in result.services] == [1, 65535]

    asyncio.run(scenario())


@pytest.mark.parametrize("stalled_stage", ["drain", "read", "close"])
def test_stalled_socket_lifecycle_is_bounded(monkeypatch, stalled_stage):
    async def scenario():
        stopped = asyncio.Event()

        async def stall(*args):
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        reader = Mock(read=AsyncMock(side_effect=stall) if stalled_stage == "read"
                      else AsyncMock(return_value=b"HTTP/1.0 200 OK\r\n\r\n"))
        writer = Mock()
        writer.drain = AsyncMock(side_effect=stall if stalled_stage == "drain" else None)
        writer.wait_closed = AsyncMock(side_effect=stall if stalled_stage == "close" else None)
        monkeypatch.setattr(asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
        result = await asyncio.wait_for(scanner._grab("127.0.0.1", 80, 0.01), 0.3)
        assert result.port == 80  # TCP observation survives missing banner/cleanup
        writer.close.assert_called_once()
        assert stopped.is_set(), "the stalled coroutine must be cancelled, not leaked"
        if stalled_stage == "close":
            writer.transport.abort.assert_called_once()

    asyncio.run(scenario())


def test_banner_reset_does_not_discard_a_connected_tcp_service(monkeypatch):
    reader = Mock(read=AsyncMock(side_effect=ConnectionResetError("loopback reset")))
    writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
    result = asyncio.run(scanner._grab("127.0.0.1", 22, 0.01))
    assert result.port == 22
    assert result.banner == ""
    assert result.ssl_trust == "not_observed"
    writer.close.assert_called_once()


def test_worker_failure_cancels_inflight_port_workers(monkeypatch):
    async def scenario():
        started, stopped = asyncio.Event(), asyncio.Event()

        async def grab(host, port, timeout):
            if port == 80:
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    stopped.set()
            await started.wait()
            raise RuntimeError("fixture worker failure")

        monkeypatch.setattr(scanner, "_grab", grab)
        with pytest.raises(RuntimeError, match="fixture worker failure"):
            await scanner.scan_host("127.0.0.1", [80, 443], concurrency=2)
        assert stopped.is_set(), "a failed scan must not leave active port workers"

    asyncio.run(scenario())


@pytest.mark.parametrize("scope", ["10.0.0.0/30,10.0.0.0/8", "fc00::/64"])
def test_oversized_direct_scope_is_rejected_before_cidr_expansion(monkeypatch, scope):
    def unexpected_expansion(network):
        raise AssertionError("CIDR expansion happened before the scope-size guard")

    monkeypatch.setattr(scanner.ipaddress.IPv4Network, "hosts", unexpected_expansion)
    monkeypatch.setattr(scanner.ipaddress.IPv6Network, "hosts", unexpected_expansion)
    with pytest.raises(ValueError, match="(?i)use.*sweep"):
        asyncio.run(scanner.scan(scope, "80"))


@pytest.mark.parametrize("concurrency", [0, -1, 1.5, True])
@pytest.mark.parametrize("entrypoint", ["host", "scan"])
def test_invalid_worker_limits_fail_before_work(monkeypatch, concurrency, entrypoint):
    grab = AsyncMock(return_value=None)
    monkeypatch.setattr(scanner, "_grab", grab)

    async def scenario():
        with pytest.raises(ValueError, match="concurrency"):
            if entrypoint == "host":
                await scanner.scan_host("127.0.0.1", [80], concurrency=concurrency)
            else:
                await asyncio.wait_for(scanner.scan(
                    "127.0.0.1", "80", host_concurrency=concurrency), 0.1)
        grab.assert_not_awaited()

    asyncio.run(scenario())


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"),
                                    float("-inf"), True, None, "2", 10**400])
@pytest.mark.parametrize("entrypoint", ["grab", "host", "scan"])
def test_invalid_timeouts_fail_before_network(monkeypatch, timeout, entrypoint):
    connection = AsyncMock(side_effect=ConnectionRefusedError("not a network call"))
    monkeypatch.setattr(asyncio, "open_connection", connection)

    async def scenario():
        with pytest.raises(ValueError, match="timeout"):
            if entrypoint == "grab":
                await scanner._grab("127.0.0.1", 80, timeout)
            elif entrypoint == "host":
                await scanner.scan_host("127.0.0.1", [80], timeout=timeout)
            else:
                await scanner.scan("127.0.0.1", "80", timeout=timeout)
        connection.assert_not_awaited()

    asyncio.run(scenario())


def test_dns_expansion_obeys_the_direct_scope_budget(monkeypatch):
    async def scenario():
        monkeypatch.setattr(scanner, "_MAX_DIRECT_HOSTS", 2)
        resolver = AsyncMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"127.0.0.{i}", 0))
            for i in range(1, 4)])
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)
        grab = AsyncMock(return_value=None)
        monkeypatch.setattr(scanner, "_grab", grab)
        with pytest.raises(ValueError, match="(?i)use.*sweep"):
            await scanner.scan("lab.example", "80")
        grab.assert_not_awaited()

    asyncio.run(scenario())


def test_callback_failure_cancels_other_host_workers(monkeypatch):
    async def scenario():
        started, stopped = asyncio.Event(), asyncio.Event()

        async def grab(host, port, timeout):
            if host == "127.0.0.2":
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    stopped.set()
            await started.wait()
            return scanner.ServiceResult(port=port)

        def callback(result):
            raise RuntimeError("fixture callback failure")

        monkeypatch.setattr(scanner, "_grab", grab)
        with pytest.raises(RuntimeError, match="fixture callback failure"):
            await scanner.scan("127.0.0.1,127.0.0.2", "80", on_host=callback)
        assert stopped.is_set(), "callback failure must not leave scanning in the background"

    asyncio.run(scenario())


def test_cancelling_close_aborts_transport_and_preserves_cancellation(monkeypatch):
    async def scenario():
        closing = asyncio.Event()

        async def wait_closed():
            closing.set()
            await asyncio.Event().wait()

        reader = Mock(read=AsyncMock(return_value=b""))
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock(side_effect=wait_closed))
        monkeypatch.setattr(asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
        task = asyncio.create_task(scanner._grab("127.0.0.1", 80, 0.5))
        await asyncio.wait_for(closing.wait(), 0.3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        writer.transport.abort.assert_called_once()

    asyncio.run(scenario())
