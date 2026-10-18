# SPDX-License-Identifier: AGPL-3.0-only
"""The Defender for Endpoint producer (#478)."""

import dataclasses
import json
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from conftest import assert_secret_free, remember_secret
from execbound_mde_producer.config import ConfigError, CoveredHost, load
from execbound_mde_producer.defender import Defender, DefenderError, Machine, project
from execbound_mde_producer.envelope import envelope, plan
from execbound_mde_producer.gateway import Answer, post
from execbound_mde_producer.run import cycle, main
from mde_fakes import FakeDefender, FakeGateway, machine

from execbound.signals.envelope import parse_signal

# A synthetic subscription: no real one is committed.
LAB = "/subscriptions/00000000-0000-0000-0000-00000000c0de/resourceGroups/edr-lab"
WIN = f"{LAB}/providers/Microsoft.Compute/virtualMachines/host-win-a"


def private(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def write_config(tmp_path: Path, **changes: object) -> Path:
    private(tmp_path / "producer.token", remember_secret("sg1." + secrets.token_urlsafe(40)))
    private(
        tmp_path / "defender.env",
        "AZURE_TENANT_ID=t\nAZURE_CLIENT_ID=c\nAZURE_CLIENT_SECRET="
        + remember_secret(secrets.token_urlsafe(32)),
    )
    value: dict[str, object] = {
        "gateway": "http://127.0.0.1:8100",
        "token_file": "producer.token",
        "defender_env": "defender.env",
        "account_id": "00000000-0000-0000-0000-00000000000a",
        "provider": "mock_crowdstrike",
        "resource_type": "endpoint",
        "hosts": [
            {
                "azure_resource_id": WIN,
                "provider_id": "device-01",
            }
        ],
    }
    value.update(changes)
    return private(tmp_path / "producer.json", json.dumps(value))


def test_a_valid_configuration_loads_with_its_files_resolved_beside_it(tmp_path):
    config = load(write_config(tmp_path))
    assert config.gateway == "http://127.0.0.1:8100"
    assert config.token_file == tmp_path / "producer.token"
    assert config.account_id == UUID(int=10)
    assert config.hosts == (CoveredHost(WIN, "device-01"),)
    assert config.interval_seconds == 60


@pytest.mark.parametrize(
    "changes",
    [
        {"gateway": "http://gateway.example.com"},
        {"gateway": "ftp://127.0.0.1"},
        {"gateway": "https://gateway.example.com/v1/signals"},
        {"gateway": "https://gateway.example.com?x=1"},
        {"interval_seconds": 241},
        {"interval_seconds": 14},
        {"interval_seconds": True},
        {"hosts": []},
        {"hosts": [{"azure_resource_id": "host-win-a", "provider_id": "device-01"}]},
        {"extra": 1},
        {"account_id": "not-a-uuid"},
        {"account_id": 4},
        {"gateway": "https://"},
        {"gateway": "https://gateway.example.com:bad"},
        {"gateway": "https://gateway.example.com:70000"},
        {"gateway": "https://gateway.example.com\n"},
        {"gateway": "https://@gateway.example.com"},
        {"gateway": "https://["},
        {"token_file": []},
    ],
)
def test_a_malformed_configuration_is_refused(tmp_path, changes):
    with pytest.raises(ConfigError):
        load(write_config(tmp_path, **changes))


def test_two_hosts_for_one_resource_or_one_provider_id_are_refused(tmp_path):
    vm = WIN
    for hosts in (
        [
            {"azure_resource_id": vm, "provider_id": "a"},
            {"azure_resource_id": vm.upper(), "provider_id": "b"},
        ],
        [
            {"azure_resource_id": vm, "provider_id": "a"},
            {"azure_resource_id": vm + "x", "provider_id": "a"},
        ],
    ):
        with pytest.raises(ConfigError):
            load(write_config(tmp_path, hosts=hosts))


@pytest.mark.parametrize("name", ["producer.token", "defender.env"])
def test_a_secret_file_anyone_else_can_read_is_refused(tmp_path, name):
    path = write_config(tmp_path)
    os.chmod(tmp_path / name, 0o640)
    with pytest.raises(ConfigError) as caught:
        load(path)
    # The refusal names the file, never its content.
    assert str(caught.value) == f"Not a private file: {name}"


CREDENTIALS = {
    "AZURE_TENANT_ID": "tenant",
    "AZURE_CLIENT_ID": "client",
    "AZURE_CLIENT_SECRET": remember_secret(secrets.token_urlsafe(32)),
}
PRODUCER_TOKEN = remember_secret("sg1." + secrets.token_urlsafe(40))


def defender(fake: FakeDefender, clock=None) -> Defender:
    timing = {} if clock is None else {"clock": clock}
    return Defender(CREDENTIALS, login=fake.base, api=fake.base, **timing)


def test_a_machine_is_read_down_to_four_fields():
    assert project(machine("m1", resource=WIN, risk="High")) == Machine("m1", "High", "Active", WIN)
    assert project(machine("m2", resource=None, risk=None)).azure_resource_id is None
    # A label Defender does not document is no verdict at all, never a guess at one.
    assert project(machine("m3", resource=WIN, risk="Severe")).risk_score is None


def test_the_token_is_taken_once_and_reused():
    with FakeDefender([machine("m1", resource=WIN)]) as fake:
        client = defender(fake)
        assert [item.machine_id for item in client.machines()] == ["m1"]
        client.machines()
        assert len(fake.token_requests) == 1
        [sent] = fake.token_requests
    assert "scope=https%3A%2F%2Fapi.securitycenter.microsoft.com%2F.default" in sent
    assert "grant_type=client_credentials" in sent


def test_the_token_is_renewed_near_expiry():
    now = [1000.0]
    with FakeDefender([machine("m1", resource=WIN)]) as fake:
        fake.expires_in = 300
        client = defender(fake, clock=lambda: now[0])
        client.machines()
        now[0] += 181
        client.machines()
        assert len(fake.token_requests) == 2


def test_a_throttled_read_says_how_long_to_wait():
    with FakeDefender([]) as fake:
        fake.throttle = True
        with pytest.raises(DefenderError) as caught:
            defender(fake).machines()
    assert (caught.value.status, caught.value.retry_after) == (429, 7)


def test_no_error_carries_the_secret():
    with FakeDefender([]) as fake:
        fake.token_status = 401
        with pytest.raises(DefenderError) as caught:
            defender(fake).machines()
    assert caught.value.status == 401
    assert_secret_free(repr(caught.value))
    assert caught.value.__suppress_context__


def test_a_next_link_is_followed_only_on_the_api_host():
    with FakeDefender([machine("m1", resource=WIN)]) as fake:
        fake.pages["/api/machines"]["@odata.nextLink"] = fake.base + "/api/machines?$skip=1"
        fake.pages["/api/machines?$skip=1"] = {"value": [machine("m2", resource=None)]}
        assert [item.machine_id for item in defender(fake).machines()] == ["m1", "m2"]
    with FakeDefender([machine("m1", resource=WIN)]) as fake:
        fake.pages["/api/machines"]["@odata.nextLink"] = "https://elsewhere.example/api/machines"
        with pytest.raises(DefenderError):
            defender(fake).machines()


@pytest.mark.parametrize("risk", [[], {}, 42, True])
def test_unrecognized_risk_shapes_are_uncovered(risk):
    assert project(machine("m1", resource=WIN, risk=risk)).risk_score is None


@pytest.mark.parametrize("page", [{}, {"value": {}}, {"value": [None]}, {"value": [{"id": 42}]}])
def test_malformed_machine_page_is_a_safe_refusal(page):
    with FakeDefender([]) as fake:
        fake.pages["/api/machines"] = page
        with pytest.raises(DefenderError) as caught:
            defender(fake).machines()
        assert_secret_free(str(caught.value))


@pytest.mark.parametrize(
    "answer",
    [
        {"access_token": "", "expires_in": 300},
        {"access_token": "bad\r\nvalue", "expires_in": 300},
        {"access_token": "bad", "expires_in": "forever"},
        {"access_token": "bad", "expires_in": -1},
    ],
)
def test_malformed_token_response_is_a_safe_refusal(answer):
    with FakeDefender([]) as fake:
        fake.token_answer = answer
        with pytest.raises(DefenderError) as caught:
            defender(fake).machines()
        assert_secret_free(str(caught.value))


def test_machine_redirect_does_not_forward_credentials():
    with FakeDefender([]) as target, FakeDefender([]) as source:
        source.redirect_read = target.base + "/api/machines"
        with pytest.raises(DefenderError):
            defender(source).machines()
        assert target.reads == []


def test_token_redirect_is_refused_without_contacting_destination():
    with FakeDefender([]) as target, FakeDefender([]) as source:
        source.redirect_token = target.base + "/token"
        with pytest.raises(DefenderError):
            defender(source).machines()
        assert target.token_requests == []


def test_environment_proxy_cannot_receive_credentials(monkeypatch):
    with FakeDefender([]) as proxy, FakeDefender([]) as source:
        monkeypatch.setenv("http_proxy", proxy.base)
        monkeypatch.setenv("HTTP_PROXY", proxy.base)
        monkeypatch.setenv("no_proxy", "")
        monkeypatch.setenv("NO_PROXY", "")
        assert defender(source).machines() == []
        assert proxy.token_requests == []
        assert proxy.reads == []


AT = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
LIN = f"{LAB}/providers/Microsoft.Compute/virtualMachines/host-lin-a"


def vm(name: str) -> str:
    return f"{LAB}/providers/Microsoft.Compute/virtualMachines/{name}"


def configured(tmp_path, hosts):
    return dataclasses.replace(load(write_config(tmp_path)), hosts=hosts)


def test_each_host_is_matched_by_its_exact_resource_id_and_nothing_else(tmp_path):
    config = configured(
        tmp_path,
        (
            CoveredHost(WIN, "device-01"),
            CoveredHost(LIN, "device-02"),
            CoveredHost(vm("gone"), "device-03"),
            CoveredHost(vm("twice"), "device-04"),
            CoveredHost(vm("quiet"), "device-05"),
        ),
    )
    machines = [
        # Azure resource ids are case-insensitive, and Defender does not keep the case.
        project(machine("m-win", resource=WIN.upper(), risk="Medium")),
        project(machine("m-lin", resource=LIN, risk="None")),
        project(machine("m-a", resource=vm("twice"))),
        project(machine("m-b", resource=vm("twice"))),
        project(machine("m-q", resource=vm("quiet"), risk=None)),
    ]
    built = plan(config, machines, AT, "0.1.0")
    assert {item["subject"]["provider_id"]: item["verdict"] for item in built.envelopes} == {
        "device-01": "Medium",
        "device-02": "None",
    }
    assert built.uncovered == ("device-03", "device-04", "device-05")


@pytest.mark.parametrize("risk", ["None", "Informational", "Low", "Medium", "High"])
def test_every_envelope_is_one_the_kernel_accepts_with_the_verdict_unmapped(tmp_path, risk):
    config = configured(tmp_path, (CoveredHost(WIN, "device-01"),))
    value = envelope(
        config, config.hosts[0], project(machine("m-win", resource=WIN, risk=risk)), AT, "0.1.0"
    )
    signal = parse_signal(json.dumps(value).encode())
    assert (signal.verdict, signal.confidence) == (risk, 1000)
    assert (signal.subject.provider_id, signal.subject.account_id) == (
        "device-01",
        config.account_id,
    )
    assert signal.attributes == {"mde_machine_id": "m-win"}
    assert signal.source_event_id == f"m-win:{int(AT.timestamp())}"
    assert signal.observed_at == AT


def against(monkeypatch, fake):
    """The command's Defender client, pointed at the fake instead of Microsoft."""
    monkeypatch.setattr(
        "execbound_mde_producer.run.Defender",
        lambda credentials, **_: Defender(credentials, login=fake.base, api=fake.base),
    )


def test_a_cycle_posts_every_matched_host_and_reports_the_rest(tmp_path):
    config = configured(tmp_path, (CoveredHost(WIN, "device-01"), CoveredHost(LIN, "device-02")))
    with FakeDefender([machine("m-win", resource=WIN, risk="High")]) as fake:
        with FakeGateway() as gateway:
            config = dataclasses.replace(config, gateway=gateway.base)
            report = cycle(config, defender(fake), PRODUCER_TOKEN, now=AT, version="0.1.0")
            [(authorization, sent)] = gateway.posts
    assert (report.posted, report.duplicates, report.uncovered) == (1, 0, ("device-02",))
    assert authorization == "Bearer " + PRODUCER_TOKEN
    assert (sent["verdict"], sent["subject"]["provider_id"]) == ("High", "device-01")


@pytest.mark.parametrize(
    "answer",
    [(200, None), (409, "CONFLICTING_DUPLICATE"), (403, "INCOMPATIBLE_PRODUCER")],
)
def test_each_answer_is_counted_where_it_belongs(tmp_path, answer):
    config = configured(tmp_path, (CoveredHost(WIN, "device-01"),))
    with FakeDefender([machine("m-win", resource=WIN)]) as fake, FakeGateway() as gateway:
        gateway.answer = answer
        config = dataclasses.replace(config, gateway=gateway.base)
        report = cycle(config, defender(fake), PRODUCER_TOKEN, now=AT, version="0.1.0")
    if answer[0] == 200:
        assert (report.duplicates, report.refused) == (1, {})
    else:
        assert (report.posted, report.refused) == (0, {answer[1]: 1})


def test_an_unreachable_gateway_is_an_answer_not_a_crash():
    assert post("http://127.0.0.1:9", PRODUCER_TOKEN, {"a": 1}) == Answer(0, "GATEWAY_UNREACHABLE")


def test_one_cycle_logs_its_counts_and_never_the_token(tmp_path, capsys, monkeypatch):
    with FakeDefender([machine("m-win", resource=WIN, risk="High")]) as fake:
        with FakeGateway() as gateway:
            path = write_config(tmp_path, gateway=gateway.base)
            against(monkeypatch, fake)
            assert main(["run", "--config", str(path), "--once"]) == 0
    [line] = capsys.readouterr().err.splitlines()
    assert_secret_free(line)
    assert json.loads(line) == {
        "event": "cycle",
        "posted": 1,
        "duplicates": 0,
        "uncovered": [],
        "refused": {},
    }


def test_the_command_stops_when_the_gateway_refuses_its_token(tmp_path, capsys, monkeypatch):
    with FakeDefender([machine("m-win", resource=WIN)]) as fake, FakeGateway() as gateway:
        gateway.answer = (401, "INVALID_SOURCE")
        path = write_config(tmp_path, gateway=gateway.base)
        against(monkeypatch, fake)
        assert main(["run", "--config", str(path), "--once"]) == 2
    printed = capsys.readouterr().err
    assert "INVALID_SOURCE" in printed
    assert_secret_free(printed)


def test_gateway_redirect_is_not_followed():
    with FakeGateway() as source, FakeDefender([]) as destination:
        source.redirect = destination.base + "/api/machines"
        assert post(source.base, PRODUCER_TOKEN, {}).status == 302
        assert destination.reads == []


def test_gateway_error_body_cannot_be_logged_as_a_secret(tmp_path, capsys, monkeypatch):
    with FakeDefender([machine("m-win", resource=WIN)]) as fake, FakeGateway() as gateway:
        gateway.answer = (403, CREDENTIALS["AZURE_CLIENT_SECRET"])
        path = write_config(tmp_path, gateway=gateway.base)
        against(monkeypatch, fake)
        main(["run", "--config", str(path), "--once"])
    assert_secret_free(capsys.readouterr().err)


@pytest.mark.parametrize(
    "file,content",
    [
        ("producer.token", b"sg1.\xff"),
        ("producer.token", b"sg1.bad\r\nInjected: value"),
        ("defender.env", b"\xff"),
    ],
)
def test_secret_file_errors_do_not_escape_the_command(tmp_path, capsys, file, content):
    path = write_config(tmp_path)
    (tmp_path / file).write_bytes(content)
    assert main(["run", "--config", str(path), "--once"]) == 2
    assert_secret_free(capsys.readouterr().err)


def test_once_exits_unsuccessfully_when_defender_cannot_be_read(tmp_path, monkeypatch, capsys):
    with FakeDefender([]) as fake:
        fake.token_status = 401
        against(monkeypatch, fake)
        assert main(["run", "--config", str(write_config(tmp_path)), "--once"]) == 1
    assert_secret_free(capsys.readouterr().err)


def test_throttle_wait_starts_after_the_failed_read(tmp_path, monkeypatch):
    class Done(Exception):
        pass

    class Throttled:
        def machines(self):
            raise DefenderError("Machines refused", status=429, retry_after=90)

    monkeypatch.setattr("execbound_mde_producer.run.Defender", lambda _: Throttled())
    ticks = iter([0.0, 30.0])
    monkeypatch.setattr("execbound_mde_producer.run.time.monotonic", lambda: next(ticks))
    waits = []

    def sleep(seconds):
        waits.append(seconds)
        raise Done

    monkeypatch.setattr("execbound_mde_producer.run.time.sleep", sleep)
    with pytest.raises(Done):
        main(["run", "--config", str(write_config(tmp_path))])
    assert waits == [90]


def test_defender_token_is_refreshed_after_a_401():
    with FakeDefender([]) as fake:
        client = defender(fake)
        client.machines()
        fake.token = remember_secret(secrets.token_urlsafe(40))
        with pytest.raises(DefenderError):
            client.machines()
        assert client.machines() == []
        assert len(fake.token_requests) == 2


def damaged_response(kind, status=200):
    if kind == "status":
        return CREDENTIALS["AZURE_CLIENT_SECRET"].encode() + b"\r\n\r\n"
    return f"HTTP/1.1 {status} Broken\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort".encode()


@pytest.mark.parametrize("kind", ["status", "chunked"])
@pytest.mark.parametrize("endpoint", ["token", "machines"])
def test_defender_protocol_errors_are_safe_refusals(kind, endpoint):
    import traceback

    from mde_fakes import RawHTTP

    with RawHTTP(damaged_response(kind)) as raw, FakeDefender([]) as good:
        client = Defender(
            CREDENTIALS,
            login=raw.base if endpoint == "token" else good.base,
            api=raw.base if endpoint == "machines" else good.base,
        )
        with pytest.raises(DefenderError) as caught:
            client.machines()
        assert_secret_free("".join(traceback.format_exception(caught.value)))


@pytest.mark.parametrize("kind,status", [("status", 200), ("chunked", 403)])
def test_gateway_protocol_errors_never_expose_the_peer_body(kind, status):
    from mde_fakes import RawHTTP

    with RawHTTP(damaged_response(kind, status)) as raw:
        answer = post(raw.base, PRODUCER_TOKEN, {})
    assert answer == (Answer(0, "GATEWAY_UNREACHABLE") if kind == "status" else Answer(403, None))
    assert_secret_free(repr(answer))


def test_continuous_mode_recovers_after_a_malformed_response(tmp_path, monkeypatch, capsys):
    from mde_fakes import RawHTTP

    body = json.dumps({"value": [machine("m-win", resource=WIN)]}).encode()
    good = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )

    class Done(Exception):
        pass

    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise Done

    with (
        RawHTTP(damaged_response("status"), good) as raw,
        FakeDefender([]) as login,
        FakeGateway() as gateway,
    ):
        monkeypatch.setattr(
            "execbound_mde_producer.run.Defender",
            lambda credentials: Defender(credentials, login=login.base, api=raw.base),
        )
        monkeypatch.setattr("execbound_mde_producer.run.time.sleep", sleep)
        with pytest.raises(Done):
            main(["run", "--config", str(write_config(tmp_path, gateway=gateway.base))])
        assert len(gateway.posts) == 1
    printed = capsys.readouterr().err
    assert_secret_free(printed)
    assert [json.loads(line)["event"] for line in printed.splitlines()] == ["defender", "cycle"]
