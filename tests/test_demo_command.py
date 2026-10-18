# SPDX-License-Identifier: AGPL-3.0-only
"""The client package's `execbound-demo` runs the demo beats from a private directory
holding the two agent credential files and a downloaded sandbox.json, with the origin from
EXECBOUND_URL, and needs no administrator credential and no repository (#247). A saved fixture
configuration stops working once the tenant holds customer context. A samples configuration,
the administrator's download for a workspace's sample targets, runs boundary and decide with one
agent's key and unmarked requests on sample hostnames alone, and never budget (SM11)."""

import importlib.metadata
import json

import httpx
import pytest
from demo_world import approve_pending, served
from demo_world import console as console
from demo_world import private as private
from execbound_client import demo
from sample_fixtures import agent_token, empty_workspace, invocations
from sample_fixtures import sample_key as sample_key
from sample_fixtures import sample_mock as sample_mock
from sample_fixtures import sample_runtime as sample_runtime
from signup_fixtures import fingerprint
from sqlalchemy import text
from test_human_surface import credential, form_values
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import samples
from execbound.execution import decide_approval


def test_the_console_script_is_declared():
    scripts = {e.name: e.value for e in importlib.metadata.entry_points(group="console_scripts")}
    assert scripts["execbound-demo"] == "execbound_client.demo:main"


def test_the_beats_run_without_an_admin_credential_and_take_the_origin_from_the_environment(
    private, console, world, db, capsys
):
    (private / "admin.token").unlink()
    document = json.loads((private / "sandbox.json").read_text(encoding="utf-8"))
    del document["credentials"]["admin"]
    document["origin"] = "https://stale.example"
    (private / "sandbox.json").write_text(json.dumps(document), encoding="utf-8")
    approvals = []

    def sleep(seconds):
        if not approvals:
            approvals.append(approve_pending(db, world))

    environ = {"EXECBOUND_URL": console}
    for beat in ("boundary", "decide"):
        status = demo.main(
            ["--private", str(private), "--run", "cmd-1", beat], sleep=sleep, environ=environ
        )
        assert status == 0, capsys.readouterr().out
    printed = capsys.readouterr().out
    record = json.loads((private / "demo-record.json").read_text(encoding="utf-8"))
    beats = {beat["beat"]: beat for beat in record["beats"]}
    assert list(beats) == ["boundary", "decide"]
    assert all(beat["failed"] is None for beat in beats.values())
    boundary = {step["label"]: step for step in beats["boundary"]["steps"]}
    assert boundary["GET /v1/me"]["kind"] == "AGENT"
    assert boundary["GET /approvals"]["status"] == 403
    assert boundary["POST /session with the agent credential"]["status"] == 403
    assert boundary["mock CrowdStrike POST /v1/contain"]["status"] == 401
    steps = {step["label"]: step for step in beats["decide"]["steps"]}
    assert steps["production isolate, after the decision"]["state"] == "EXECUTED"
    lie = next(step for label, step in steps.items() if "claiming the domain controller" in label)
    assert lie["refused"] == "EXECUTION_UNAVAILABLE"
    for name in ("agent-a.token", "agent-b.token"):
        token = (private / name).read_text(encoding="ascii").strip()
        assert token not in printed and token not in json.dumps(record)


@pytest.mark.parametrize("transport", ["http", "mcp"])
def test_saved_demo_configuration_cannot_run_after_customer_context_is_imported(
    private, world, db, admin_engine, live_provider, transport
):
    from execbound_client.demo import Driver, Record, Sandbox
    from signup_fixtures import fingerprint
    from test_context_provisioning import apply, entry, manifest

    sandbox = Sandbox.load(private, {})
    document = manifest(world, entry(world["clock"].now(), facts={"role": "workstation"}))
    apply(admin_engine, world, document)
    tenant = world["identity"].tenant_id
    before = fingerprint(admin_engine, tenant)
    driver = Driver(
        sandbox, Record(private / "demo-record.json", "saved", str(tenant)), run="saved"
    )
    try:
        steps = []
        request = driver.request("decide", sandbox.targets["workstation"])
        send = driver.send if transport == "http" else driver.send_mcp
        assert send("agent_a", steps, "saved configuration", request) is None
        assert steps[-1]["refused"] == "DEMO_UNAVAILABLE"
    finally:
        driver.close()
    after = fingerprint(admin_engine, tenant)
    for table in ("executions", "approvals", "execution_impact", "execution_keys"):
        assert after[table] == before[table]


# A Community workspace's sample targets (#247): the administrator's download names them, and the
# demo runs the beats they can carry with one agent's API key alone.

SAMPLE_TARGETS = {
    "workstation": "ws-dev-01.sample.invalid",
    "domain_controller": "dc-01.sample.invalid",
    "production": "ws-prod-01.sample.invalid",
}


def samples_directory(directory, **changes):
    """A private directory holding a samples configuration and the one agent key file it
    names; the other key files lie beside it for the cases that name them."""
    document = {
        "workspace": "samples",
        "origin": "http://127.0.0.1:9",
        "tenant_id": "11111111-1111-4111-8111-111111111111",
        "providers": {},
        "targets": {
            **{
                name: {
                    "kind": "hostname",
                    "value": value,
                    "incident_id": f"22222222-2222-4222-8222-00000000000{index}",
                }
                for index, (name, value) in enumerate(SAMPLE_TARGETS.items())
            },
            "pool": [],
        },
        "credentials": {"agent_a": "agent-a.token"},
    }
    for path, value in changes.items():
        *parents, last = path.split(".")
        place = document
        for parent in parents:
            place = place[parent]
        place[last] = value
    for name in ("agent-a.token", "agent-b.token", "admin.token"):
        (directory / name).write_text("ebt1." + name.split(".")[0] + "\n", encoding="ascii")
    (directory / "sandbox.json").write_text(json.dumps(document), encoding="utf-8")
    return directory


def test_sm11_a_samples_configuration_loads_with_no_pool_and_marks_nothing_synthetic(tmp_path):
    sandbox = demo.Sandbox.load(samples_directory(tmp_path), {})
    assert sandbox.workspace == "samples" and not sandbox.synthetic
    assert sandbox.pool == ()
    assert {name: target.value for name, target in sandbox.targets.items()} == SAMPLE_TARGETS
    # A fixture configuration still needs its pool and both agents' keys, and one that names no
    # workspace is one.
    both = {"agent_a": "agent-a.token", "agent_b": "agent-b.token"}
    with pytest.raises(demo.SandboxError, match="non-empty"):
        demo.Sandbox.load(samples_directory(tmp_path, workspace="fixtures", credentials=both), {})
    document = json.loads((tmp_path / "sandbox.json").read_text(encoding="utf-8"))
    del document["workspace"]
    document["targets"]["pool"] = [document["targets"]["workstation"]]
    (tmp_path / "sandbox.json").write_text(json.dumps(document), encoding="utf-8")
    fixtures = demo.Sandbox.load(tmp_path, {})
    assert fixtures.workspace == "fixtures" and fixtures.synthetic


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"workspace": "sandbox"}, "workspace"),
        ({"targets.workstation.value": "ws01.example"}, "sample.invalid"),
        ({"targets.production.value": "WS-PROD-01.sample.invalid"}, "sample.invalid"),
        ({"targets.domain_controller.kind": "provider_id"}, "hostname"),
        (
            {
                "targets.pool": [
                    {
                        "kind": "canonical",
                        "value": "33333333-3333-4333-8333-333333333333",
                        "incident_id": "44444444-4444-4444-8444-444444444444",
                    }
                ]
            },
            "hostname",
        ),
        (
            {
                "credentials": {
                    "agent_a": "agent-a.token",
                    "agent_b": "agent-b.token",
                    "admin": "admin.token",
                }
            },
            "admin",
        ),
    ],
)
def test_sm11_a_samples_configuration_names_sample_hostnames_and_agent_keys_only(
    tmp_path, change, message
):
    """Requests on samples carry no `synthetic_demo` mark, so the client itself refuses a
    configuration that would aim them at anything but a sample target, or that puts an
    administrator's credential on the demo machine."""
    with pytest.raises(demo.SandboxError, match=message):
        demo.Sandbox.load(samples_directory(tmp_path, **change), {})


def test_sm11_a_samples_configuration_needs_only_the_key_its_beats_send_with(tmp_path):
    """`boundary` and `decide` send as agent A alone, and `budget`, the one beat that uses a
    second agent, never runs on samples, so a samples file needs one live agent key on the
    demo machine. A second, which it never sends, is accepted; a fixture file still needs
    both, since its budget beat splits the requests between them."""
    sandbox = demo.Sandbox.load(samples_directory(tmp_path), {})
    assert set(sandbox.tokens) == {"agent_a"}
    both = {"agent_a": "agent-a.token", "agent_b": "agent-b.token"}
    assert set(demo.Sandbox.load(samples_directory(tmp_path, credentials=both), {}).tokens) == {
        "agent_a",
        "agent_b",
    }
    for credentials in ({}, {"agent_b": "agent-b.token"}):
        with pytest.raises(demo.SandboxError, match="agent_a"):
            demo.Sandbox.load(samples_directory(tmp_path, credentials=credentials), {})
    document = json.loads((tmp_path / "sandbox.json").read_text(encoding="utf-8"))
    document["credentials"] = {"agent_a": "agent-a.token"}
    del document["workspace"]
    document["targets"]["pool"] = [document["targets"]["workstation"]]
    (tmp_path / "sandbox.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(demo.SandboxError, match="agent_a and agent_b"):
        demo.Sandbox.load(tmp_path, {})


@pytest.mark.parametrize(
    ("workspace", "origin", "environ", "provider", "loads"),
    [
        ("samples", "https://console.example", {}, "https://endpoint.example", True),
        ("samples", "http://127.0.0.1:9", {}, "http://127.0.0.1:8001", True),
        ("samples", "http://localhost:9", {}, "http://[::1]:8001", True),
        ("samples", "https://console.example", {}, "http://127.0.0.1:8001", False),
        ("samples", "https://console.example", {}, "https://localhost:8443", False),
        # The origin the demo sends to is EXECBOUND_URL's, when it is set, not the file's.
        (
            "samples",
            "http://127.0.0.1:9",
            {"EXECBOUND_URL": "https://console.example"},
            "http://127.0.0.1:8001",
            False,
        ),
        ("fixtures", "https://console.example", {}, "http://127.0.0.2:8001", False),
        ("fixtures", "http://127.0.0.1:9", {}, "http://127.0.0.1:8001", True),
    ],
)
def test_sm11_a_loopback_mock_is_named_only_beside_a_loopback_gateway(
    tmp_path, workspace, origin, environ, provider, loads
):
    """The boundary beat sends agent A's key to every origin `providers` names, to show the
    mock refusing it. A loopback address names the gateway's own mock only when the gateway is
    on this machine's loopback too; beside a gateway published elsewhere it is whatever listens
    on that port here, which would be handed the key. So the command refuses such a file before
    anything is sent, whichever kind of workspace it describes."""
    changes = {"workspace": workspace, "origin": origin, "providers": {"endpoint": provider}}
    if workspace == "fixtures":
        changes["credentials"] = {"agent_a": "agent-a.token", "agent_b": "agent-b.token"}
        changes["targets.pool"] = [
            {
                "kind": "hostname",
                "value": "ws-dev-02.sample.invalid",
                "incident_id": "22222222-2222-4222-8222-000000000009",
            }
        ]
    directory = samples_directory(tmp_path, **changes)
    if loads:
        assert demo.Sandbox.load(directory, environ).providers == {"endpoint": provider}
    else:
        with pytest.raises(demo.SandboxError, match="loopback"):
            demo.Sandbox.load(directory, environ)


@pytest.mark.parametrize(
    ("unreachable", "said"),
    [
        ("127.0.0.1:8001", "the endpoint provider at http://127.0.0.1:8001 could not be reached"),
        ("127.0.0.1:9", "the gateway at http://127.0.0.1:9 could not be reached"),
    ],
)
def test_sm11_an_origin_this_machine_cannot_reach_fails_the_boundary_beat_and_says_so(
    tmp_path, monkeypatch, capsys, unreachable, said
):
    """A file may name an origin the demo machine cannot reach: a mock a person named by hand at
    a loopback address the gateway publishes no port for, as the Community bundle does with its
    mock, or a gateway that is down. The beat then fails as a beat, its record saved and the
    reason said, and `all` stops there, rather than the command ending in a traceback with
    nothing recorded."""
    directory = samples_directory(tmp_path, providers={"endpoint": "http://127.0.0.1:8001"})
    form = '<input type="hidden" name="csrf" value="' + "c" * 43 + '">'

    def answering(client, request, **options):
        if request.url.netloc.decode() == unreachable:
            raise httpx.ConnectError("refused", request=request)
        if request.url.path == "/v1/me":
            return httpx.Response(200, json={"kind": "AGENT", "principal_id": "p"}, request=request)
        if request.url.path == "/login":
            return httpx.Response(200, text=form, request=request)
        return httpx.Response(403, json={"code": "FORBIDDEN"}, request=request)

    monkeypatch.setattr(httpx.Client, "send", answering)
    status = demo.main(["--private", str(directory), "--run", "far", "all"], environ={})
    printed = capsys.readouterr()
    assert status == 2
    assert said in printed.err and "Traceback" not in printed.err
    record = json.loads((directory / "demo-record.json").read_text(encoding="utf-8"))
    assert [beat["beat"] for beat in record["beats"]] == ["boundary"]
    (beat,) = record["beats"]
    assert said in beat["failed"]
    assert beat["steps"][-1]["unreachable"] == "ConnectError"
    assert "ebt1.agent-a" not in printed.out + printed.err + json.dumps(record)


@pytest.mark.parametrize("state", ["STALE_AUTHORIZATION", "FAILED_NOT_EXECUTED", "DENIED"])
def test_sm11_an_isolation_that_did_not_execute_is_blamed_on_an_earlier_one_only_when_stale(state):
    """On samples, an isolation the decide beat expects to execute that the provider found past
    the version the facts record ends `STALE_AUTHORIZATION`, which an earlier executed isolation
    of the target causes, by a run or by the person's own agent, and a refresh mends. Any other
    outcome is not one, so the beat names no earlier request and offers no refresh for it."""
    said = demo.samples_outcome("the workstation isolation", state)
    assert said.startswith(f"the workstation isolation ended {state}, not EXECUTED")
    earlier = "isolated one since their facts were recorded" in said
    assert earlier == ("refresh the sample facts" in said) == (state == "STALE_AUTHORIZATION")


@pytest.mark.parametrize(
    ("status", "body", "said", "advice"),
    [
        # Facts gone stale, or no longer naming the target: the one refusal a refresh mends.
        (503, {"code": "EXECUTION_UNAVAILABLE"}, "(503 EXECUTION_UNAVAILABLE)", "refresh"),
        # An agent key that expired or was revoked: the gateway answers before any fact is read.
        (401, {"detail": "Invalid credentials"}, "does not accept agent A's API key", "key"),
        # An emergency stop refuses every new request before resolution.
        (423, {"code": "TENANT_STOPPED"}, "under an emergency stop", "stop"),
        # An agent in a space with no policy: the starter decides the default space's agents.
        (409, {"code": "NO_ACTIVE_BUNDLE"}, "the agent's space has no active policy", "space"),
        # Anything else is named, and pointed at the reference that explains it.
        (429, {"code": "BUSY"}, "(429 BUSY)", "reference"),
    ],
)
@pytest.mark.parametrize("workspace", ["samples", "fixtures"])
def test_sm11_a_refused_first_isolation_is_blamed_on_the_facts_only_when_they_cause_it(
    tmp_path, monkeypatch, capsys, workspace, status, body, said, advice
):
    """The decide beat's first request is the workstation isolation. A refusal of it says the
    code the gateway answered with, and only `EXECUTION_UNAVAILABLE`, which stale facts or facts
    that no longer name the target cause, sends the person to refresh them and download the file
    again. An expired or revoked agent key, an emergency stop and an agent whose space has no
    policy refuse every request alike, which no refresh or new download changes, so each says
    what does; and a refusal it has no words for names its code and where it is explained."""
    changes: dict = {"workspace": workspace}
    if workspace == "fixtures":
        changes["credentials"] = {"agent_a": "agent-a.token", "agent_b": "agent-b.token"}
        changes["targets.pool"] = [
            {
                "kind": "hostname",
                "value": "ws-dev-02.sample.invalid",
                "incident_id": "22222222-2222-4222-8222-000000000009",
            }
        ]
    directory = samples_directory(tmp_path, **changes)

    def answering(client, request, **options):
        assert (request.method, request.url.path) == ("POST", "/v1/execute")
        return httpx.Response(status, json=body, request=request)

    monkeypatch.setattr(httpx.Client, "send", answering)
    exit_status = demo.main(["--private", str(directory), "--run", "no", "decide"], environ={})
    printed = capsys.readouterr()
    assert exit_status == 2
    (beat,) = json.loads((directory / "demo-record.json").read_text(encoding="utf-8"))["beats"]
    assert beat["steps"] == [
        {
            "label": "workstation isolate",
            "refused": body.get("code", "UNKNOWN"),
            "status": status,
        }
    ]
    failed = beat["failed"]
    assert failed.startswith("the workstation isolation was refused") and said in failed
    assert failed in printed.err and "Traceback" not in printed.err
    facts = "refresh the sample facts" if workspace == "samples" else "record them again"
    assert (facts in failed) == (advice == "refresh")
    assert ("issue a new one" in failed) == (advice == "key")
    assert ("until an administrator lifts it" in failed) == (advice == "stop")
    assert ("an agent in the default space" in failed) == (
        advice == "space" and workspace == "samples"
    )
    assert ("agent API reference" in failed) == (advice == "reference")


def test_sm11_the_recording_driver_refuses_a_samples_configuration(tmp_path):
    """The recording's replay beat reads the history with an administrator's credential, which
    a samples configuration never names."""
    with pytest.raises(demo.SandboxError, match="admin"):
        demo.Sandbox.load(samples_directory(tmp_path), {}, require_admin=True)


def signed_in(browser, origin, admin_engine, identity):
    """Sign one person in through the login form of a served console, as a browser does."""
    _, values = form_values(browser.get("/login").text, "/session")
    values["credential"] = credential(admin_engine, identity)
    opened = browser.post("/session", data=values, headers={"Origin": origin})
    assert opened.status_code == 303, opened.text


def approve_held(db, workspace, clock):
    """The administrator who added the samples approves the newest held request, as they would
    on their phone: review of the samples is theirs alone."""
    with db.transaction(workspace.tenant_id) as conn:
        approval_id = conn.execute(
            text(
                "SELECT approval_id FROM execbound.approvals "
                "WHERE tenant_id=:t AND state='PENDING' ORDER BY created_at DESC LIMIT 1"
            ),
            {"t": workspace.tenant_id},
        ).scalar_one_or_none()
    if approval_id is not None:
        decide_approval(db, workspace.admin, approval_id, "APPROVE", clock)
    return approval_id


def sent_intents(monkeypatch):
    """Every intent the demo's clients put on the wire, as the gateway received it: the body of
    each `POST /v1/execute`, read off httpx's own transport call. A request the gateway refused
    before writing anything is here too, which a count of execution rows would never see."""
    sent: list[dict] = []
    send = httpx.Client.send

    def recording(client, request, **options):
        if request.method == "POST" and request.url.path == "/v1/execute":
            sent.append(json.loads(request.content))
        return send(client, request, **options)

    monkeypatch.setattr(httpx.Client, "send", recording)
    return sent


@pytest.mark.integration
def test_sm11_the_demo_runs_on_a_workspaces_sample_targets_from_the_administrators_download(
    db, admin_engine, seeded, tmp_path, sample_mock, sample_runtime, capsys, monkeypatch
):

    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True, clock=sample_runtime.clock)
    hosts = {host.effect: host for host in installed.hosts}
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    # One agent's key: the beats a samples file runs send as agent A alone.
    tokens = {"agent-a": agent_token(admin_engine, workspace)}
    (private / "agent-a.token").write_text(tokens["agent-a"] + "\n", encoding="ascii")
    with (
        served(db, sample_runtime) as origin,
        httpx.Client(base_url=origin, trust_env=False) as browser,
    ):
        signed_in(browser, origin, admin_engine, workspace.admin)
        download = browser.get("/api/console/v1/samples/demo-configuration")
        assert download.status_code == 200, download.text
        document = download.json()
        # The download is the whole configuration but the agent's key file.
        assert document["workspace"] == "samples" and document["origin"] == origin
        # The mock is on loopback, which the gateway cannot know the person's machine reaches
        # as it does, so the download names none; this machine does, so the person names it.
        assert "providers" not in document
        document["providers"] = {"endpoint": sample_mock.config.origin}
        document["credentials"] = {"agent_a": "agent-a.token"}
        (private / "sandbox.json").write_text(json.dumps(document), encoding="utf-8")
        approvals = []

        def sleep(seconds):
            if not approvals:
                approvals.append(approve_held(db, workspace, sample_runtime.clock))

        sent = sent_intents(monkeypatch)
        status = demo.main(
            ["--private", str(private), "--run", "samples-1", "all"], sleep=sleep, environ={}
        )
        printed = capsys.readouterr()
        # What went out, before what came back: every intent the run sent, refused ones too,
        # named a sample hostname and carried no fixture mark, which this workspace's gateway
        # refuses before it writes anything.
        assert [intent for intent in sent if "synthetic_demo" in intent] == []
        assert {intent["target"]["value"] for intent in sent} == {
            hosts[effect].hostname for effect in ("allow", "deny", "require approval")
        }
        assert len(sent) >= 6
        assert status == 0, printed.out + printed.err
        assert approvals and approvals[0] is not None
        assert "budget needs a synthetic-fixture workspace" in printed.out

        record = json.loads((private / "demo-record.json").read_text(encoding="utf-8"))
        beats = {beat["beat"]: beat for beat in record["beats"]}
        assert list(beats) == ["boundary", "decide"]
        assert all(beat["failed"] is None for beat in beats.values())
        boundary = {step["label"]: step for step in beats["boundary"]["steps"]}
        assert boundary["GET /v1/me"]["kind"] == "AGENT"
        assert boundary["GET /approvals"]["status"] == 403
        assert boundary["POST /session with the agent credential"]["status"] == 403
        assert boundary["endpoint POST /v1/contain"]["status"] == 401
        steps = {step["label"]: step for step in beats["decide"]["steps"]}
        executed = steps["workstation isolate"]
        assert executed["state"] == "EXECUTED"
        assert steps["workstation isolate, same key"]["execution_id"] == executed["execution_id"]
        assert steps["domain controller isolate"]["state"] == "DENIED"
        lie = next(step for label, step in steps.items() if "the domain controller's" in label)
        assert lie["label"].startswith(hosts["allow"].hostname)
        assert lie["refused"] == "EXECUTION_UNAVAILABLE"
        assert steps["production isolate"]["state"] == "PENDING_APPROVAL"
        assert steps["agent tries to approve"]["status"] >= 400
        assert steps["production isolate, after the decision"]["state"] == "EXECUTED"
        assert len(invocations(sample_mock)) == 2
        for token in tokens.values():
            assert token not in printed.out + printed.err
            assert token not in json.dumps(record)

        # The shared tenant total cannot be reached with one allowed target: the beat says so
        # and sends nothing.
        before = fingerprint(admin_engine, workspace.tenant_id)
        refused = demo.main(
            ["--private", str(private), "--run", "samples-1", "budget"], sleep=sleep, environ={}
        )
        printed = capsys.readouterr()
        assert refused == 2
        assert "synthetic-fixture workspace" in printed.err
        assert fingerprint(admin_engine, workspace.tenant_id) == before

        # The development and production workstations are isolated now, past the version the
        # facts record, so the card offers no file until a refresh, and says that a refresh is
        # what it waits for; a run of the old file stops and says why, never blaming a step the
        # person did not take.
        status = browser.get("/api/console/v1/samples").json()
        assert (status["demo_available"], status["demo_needs_refresh"]) == (False, True)
        assert browser.get("/api/console/v1/samples/demo-configuration").status_code == 404
        again = demo.main(
            ["--private", str(private), "--run", "samples-2", "decide"], sleep=sleep, environ={}
        )
        printed = capsys.readouterr()
        assert again == 2
        assert "STALE_AUTHORIZATION" in printed.err
        assert "isolated one since their facts were recorded" in printed.err
        assert "refresh the sample facts" in printed.err

        # Which is the whole of it: refreshed and downloaded again, the next run goes through.
        samples.refresh(db, workspace.admin, available=True, clock=sample_runtime.clock)
        refreshed = browser.get("/api/console/v1/samples/demo-configuration").json()
        assert refreshed["targets"] != document["targets"]
        refreshed["credentials"] = document["credentials"]
        refreshed["providers"] = document["providers"]
        (private / "sandbox.json").write_text(json.dumps(refreshed), encoding="utf-8")
        approvals.clear()
        after_refresh = demo.main(
            ["--private", str(private), "--run", "samples-3", "decide"], sleep=sleep, environ={}
        )
        printed = capsys.readouterr()
        assert after_refresh == 0, printed.out + printed.err
        assert approvals and approvals[0] is not None
