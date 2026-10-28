"""CLI integration for offline coverage planning and reliable job resumes."""
import asyncio
import json
import socket
from unittest.mock import AsyncMock, Mock

import cli
import pytest


def test_plan_cli_is_offline_and_reports_all_tcp_workload(capsys, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("offline planner must not resolve or connect")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert cli.main(["plan", "public-ipv4", "-p", "all-tcp", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["offline"] is True
    assert data["transport"] == "tcp"
    assert data["port_count"] == 65535
    assert data["attempt_count"] == data["address_count"] * data["port_count"]
    assert data["required_rate"] > 1_000_000
    assert any("UDP" in warning for warning in data["warnings"])


def test_cli_resume_restores_configuration_and_safe_prefix(empty_index, monkeypatch):
    from rennacs import sweep as sweepmod

    config = {"version": 2, "ports": [22, 80], "shuffle": False,
              "timeout": 0.25, "rate": 12.0, "concurrency": 2, "progress_every": 1}
    job_id = empty_index.start_job("127.0.0.0/29", "22,80", 6, seed=0, config=config)
    empty_index.checkpoint_job(job_id, scanned=3, resume_at=1, hosts_up=1, services=2)

    async def fake_sweep(scope, port_spec, **kwargs):
        assert kwargs["start_at"] == 1
        assert kwargs["shuffle"] is False
        assert kwargs["timeout"] == 0.25
        assert kwargs["rate"] == 12.0
        assert kwargs["concurrency"] == 2
        assert kwargs["progress_every"] == 1
        assert port_spec == "22,80"
        stats = sweepmod.SweepStats(total=6, scanned=6, hosts_up=5, services=10,
                                    resume_at=6, resume_hosts_up=5, resume_services=10)
        kwargs["on_progress"](stats, 0)
        return stats

    monkeypatch.setattr(sweepmod, "sweep", fake_sweep)
    assert cli.main(["--db", empty_index.path, "sweep", "--resume", str(job_id)]) == 0
    job = empty_index.get_job(job_id)
    assert job["status"] == "done"
    assert (job["resume_at"], job["hosts_up"], job["services"]) == (6, 6, 12)


@pytest.mark.parametrize("option", [
    ["-p", "65536"], ["--rate", "-1"], ["--timeout", "0"],
    ["--checkpoint-every", "0"], ["--concurrency", "0"],
    ["--repeat", "-1"], ["--interval", "-1"],
])
def test_bad_sweep_cli_never_creates_a_job(empty_index, option, monkeypatch):
    from rennacs import scanner

    async def fake(*args):
        return None

    monkeypatch.setattr(scanner, "_grab", fake)
    assert cli.main(["--db", empty_index.path, "sweep", "127.0.0.1/32", *option]) == 2
    assert empty_index.list_jobs() == []


def test_connector_failure_records_a_resumable_failed_job(empty_index, monkeypatch):
    from rennacs import sweep as sweepmod

    async def fail(*args, **kwargs):
        raise OSError("local fixture connector failed")

    monkeypatch.setattr(sweepmod, "sweep", fail)
    assert cli.main(["--db", empty_index.path, "sweep", "127.0.0.1/32", "-p", "80"]) == 1
    job = empty_index.list_jobs()[0]
    assert job["status"] == "failed"
    assert job["resume_at"] == 0
    assert empty_index.resumable_jobs()[0]["id"] == job["id"]


def test_scan_does_not_count_unknown_empty_hosts(empty_index, monkeypatch, capsys):
    from rennacs import scanner

    async def no_observations(*args, on_host=None, **kwargs):
        on_host(scanner.HostResult(ip="127.0.0.1", scanned_ports=[80]))
        return []

    monkeypatch.setattr(scanner, "scan", no_observations)
    assert cli.main(["--db", empty_index.path, "scan", "127.0.0.1", "-p", "80"]) == 0
    assert "Done. 0 host(s), 0 service(s)" in capsys.readouterr().out
    assert empty_index.host("127.0.0.1") is None


@pytest.fixture
def scan_cli_dependencies(tmp_path, monkeypatch):
    """Exercise the real CLI/scanner/index without any DNS or TCP traffic."""
    index = cli.Index(str(tmp_path / "scan.db"))
    real_close = index.close
    monkeypatch.setattr(index, "close", Mock(wraps=real_close))
    monkeypatch.setattr(cli, "Index", Mock(return_value=index))
    resolver = AsyncMock(return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
         ("127.0.0.1", 0)),
    ])
    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", resolver)
    grab = AsyncMock(return_value=None)
    monkeypatch.setattr(cli.scanner, "_grab", grab)
    try:
        yield index, resolver, grab
    finally:
        if not index.close.called:
            real_close()  # also release the fixture DB during the RED run


@pytest.mark.parametrize("failure", [
    pytest.param(socket.gaierror(socket.EAI_NONAME, "fixture DNS failure"), id="gaierror"),
    pytest.param(TimeoutError("fixture DNS timeout"), id="timeout"),
])
def test_scan_dns_failure_is_controlled_and_closes_index(
        scan_cli_dependencies, capsys, failure):
    index, resolver, grab = scan_cli_dependencies
    resolver.side_effect = failure

    assert cli.main([
        "--db", index.path, "scan", "127.0.0.2,lab.example", "-p", "80",
    ]) == 1

    resolver.assert_awaited_once_with(
        "lab.example", None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    grab.assert_not_called()
    index.close.assert_called_once_with()
    output = capsys.readouterr()
    assert "[FAILED]" in output.err
    assert str(failure) in output.err
    assert "Done." not in output.out
    assert "No open ports found" not in output.out


@pytest.mark.parametrize("stage", ["output", "resolver", "connector", "index"])
def test_scan_unexpected_failure_propagates_and_closes_index(
        scan_cli_dependencies, monkeypatch, capsys, stage):
    index, resolver, grab = scan_cli_dependencies
    failure = RuntimeError("fixture programming failure")
    if stage == "output":
        monkeypatch.setattr(cli, "print", Mock(side_effect=failure), raising=False)
    elif stage == "resolver":
        resolver.side_effect = failure
    elif stage == "connector":
        grab.side_effect = failure
    else:
        grab.return_value = cli.scanner.ServiceResult(port=80)
        monkeypatch.setattr(index, "upsert_host", Mock(side_effect=failure))

    with pytest.raises(RuntimeError, match="fixture programming failure") as raised:
        cli.main(["--db", index.path, "scan", "lab.example", "-p", "80"])

    assert raised.value is failure
    if stage == "output":
        resolver.assert_not_called()
    else:
        resolver.assert_awaited_once()
    if stage in {"output", "resolver"}:
        grab.assert_not_called()
    else:
        grab.assert_awaited_once_with("127.0.0.1", 80, 2.0)
    index.close.assert_called_once_with()
    output = capsys.readouterr()
    assert output.err == ""
    assert "Done." not in output.out


@pytest.mark.parametrize("open_port", [False, True], ids=["empty", "live"])
def test_scan_success_closes_index_once_and_preserves_summary(
        scan_cli_dependencies, capsys, open_port):
    index, resolver, grab = scan_cli_dependencies
    if open_port:
        grab.return_value = cli.scanner.ServiceResult(port=80, product="nginx")

    assert cli.main([
        "--db", index.path, "scan", "lab.example", "-p", "80",
    ]) == 0

    resolver.assert_awaited_once()
    grab.assert_awaited_once_with("127.0.0.1", 80, 2.0)
    index.close.assert_called_once_with()
    output = capsys.readouterr()
    count = 1 if open_port else 0
    assert (f"Done. {count} host(s), {count} service(s) indexed into {index.path}."
            in output.out)
    assert ("No open ports found" in output.out) is (not open_port)
    if open_port:
        assert "1 open  [80(nginx)]" in output.out
    assert output.err == ""


def test_scan_authorization_refusal_closes_index_once_without_probes(
        scan_cli_dependencies, capsys):
    index, resolver, grab = scan_cli_dependencies
    resolver.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
         ("198.51.100.1", 0)),
    ]

    assert cli.main([
        "--db", index.path, "scan", "127.0.0.2,lab.example", "-p", "80",
    ]) == 2

    resolver.assert_awaited_once()
    grab.assert_not_called()
    index.close.assert_called_once_with()
    output = capsys.readouterr()
    assert "[REFUSED]" in output.err
    assert "198.51.100.1" in output.err
    assert "[FAILED]" not in output.err
    assert "Done." not in output.out
    assert "No open ports found" not in output.out


def test_cli_defaults_cover_multiple_service_families():
    for command in ("scan", "sweep"):
        args = cli.build_parser().parse_args([command, "127.0.0.1"])
        assert args.ports == "multiservice"
