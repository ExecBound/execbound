# SPDX-License-Identifier: AGPL-3.0-only
"""The Policy pages under `/` in real Chromium (#333): Policy, a bundle, and the lifecycle.

The list and the detail are axe-clean with zero policy or Trusted Types violations in both
schemes and at 390 pixels, through the same `audit` the kit's pages pass. Then the walk a
person takes: a draft pasted, validated, previewed over a window, and activated behind a
confirmation that names the bundle it retires and what the preview found; a changed decision
linking to the record in Activity's drawer; a rule's note rendering as text; and retiring the
selection requiring a replacement before it can be retired.
"""

import json
import re
from uuid import UUID, uuid4

import pytest
from playwright.sync_api import expect
from scope_fixtures import group
from scope_fixtures import owner as owner
from space_fixtures import make_space
from sqlalchemy import text
from test_browser_console import AXE_RUN, audit, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import FITS
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import pending
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.policy.models import Rule, Ruleset
from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import (
    activate_bundle,
    create_bundle,
    read_bundle,
    retire_bundle,
    validate_bundle,
)
from execbound_harness.demo import ENDPOINT_RULESET, endpoint_bundle

MARKUP = "<img src=x onerror=alert(1)>"


# A dialog rises over 160 ms from opacity 0, and axe reads the opacity of that moment as a
# contrast failure, so the question is asked of the settled page: nothing still animating, and
# every surface that rises fully opaque. Waiting on `getAnimations` alone is not enough, because
# the animation of a surface React has only just mounted may not have started yet. The stop
# dialog showed this first; this file takes the same wait rather than a second spelling of it.
def clean(page, what):
    """axe over the settled page, with whatever surface is open counted as part of it."""
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (what, violations)
    assert page.evaluate("window.__violations") == [], what


def document(world, **changes) -> str:
    bundle = endpoint_bundle(
        world["identity"].tenant_id, world["account"], mapping_version="map-v1"
    )
    return bundle.model_copy(update={"bundle_id": uuid4(), **changes}).model_dump_json()


def paste(page, text: str) -> None:
    """Fill the draft textarea without typing 4 KB of JSON one key at a time."""
    page.get_by_text("Advanced: import or copy complete configuration", exact=True).click()
    page.get_by_label("Bundle JSON").fill(text)


@pytest.fixture
def noted_bundle(db, world):
    """The endpoint pack as rules, active, with a note carrying markup on its first rule."""
    rules = list(ENDPOINT_RULESET.rules)
    rules[0] = rules[0].model_copy(update={"note": MARKUP})
    content = ruleset_bundle(
        Ruleset(rules=tuple(rules), budgets=ENDPOINT_RULESET.budgets),
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    assert isinstance(rules[0], Rule)
    return content


@pytest.fixture
def validated_bundle(db, world, noted_bundle):
    """A validated draft written as rules beside the active one, with a retired version, so
    the stepper, the comparison and the folded list all have something to show."""
    rules = (
        *ENDPOINT_RULESET.rules,
        Rule(id="allow-more", action="endpoint.isolate", effect="ALLOW"),
    )
    content = ruleset_bundle(
        Ruleset(rules=rules, budgets=ENDPOINT_RULESET.budgets),
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    retire_bundle(db, world["admin"], world["bundle"].bundle_id, world["clock"])
    return content


def no_sideways_scroll(page, what) -> None:
    assert page.evaluate(FITS), (what, "horizontal scroll")


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_the_policy_pages_are_clean_in_both_schemes_and_at_phone_width(
    console_page, admin_engine, world, noted_bundle, validated_bundle, scheme
):
    """PL10: the list, the list with its retired versions, an active policy and a validated
    one, at 1280 and 390 pixels in both schemes, and the activation dialog open once."""
    console_page.emulate_media(color_scheme=scheme)
    sign_in_as(console_page, admin_engine, world["admin"])
    validated = str(validated_bundle.bundle_id)
    pages = [
        ("/policy", "Policies"),
        ("/policy?retired=1", "Policies"),
        (f"/policy/{noted_bundle.bundle_id}", f"Policy version {str(noted_bundle.bundle_id)[:8]}"),
        (f"/policy/{validated}", f"Policy version {validated[:8]}"),
    ]
    for width in (1280, 390):
        console_page.set_viewport_size({"width": width, "height": 900 if width > 400 else 780})
        for path, heading in pages:
            audit(console_page, path, heading)
        expect(
            console_page.get_by_role("heading", name="Changes from the active policy")
        ).to_be_visible()
        console_page.get_by_role("button", name="Activate", exact=True).click()
        dialog = console_page.get_by_role("dialog")
        expect(dialog.get_by_label(re.compile("What changed and why"))).to_be_visible()
        clean(console_page, f"the activation dialog at {width}")
        no_sideways_scroll(console_page, f"the activation dialog at {width}")
        dialog.get_by_role("button", name="Cancel").click()
        expect(dialog).to_have_count(0)


def test_a_bundle_reads_its_rules_as_sentences_with_a_note_as_text(
    console_page, admin_engine, world, noted_bundle
):
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto(f"/policy/{noted_bundle.bundle_id}")
    expect(console_page.get_by_role("heading", level=1)).to_have_text(
        f"Policy version {str(noted_bundle.bundle_id)[:8]}"
    )
    expect(console_page.get_by_text("As the rules read")).to_be_visible()
    # The note is text: it renders as the characters it is and creates no element.
    expect(console_page.get_by_text(f"Note: {MARKUP}")).to_be_visible()
    assert console_page.locator("img").count() == 0
    assert console_page.evaluate("window.__violations") == []
    # The compiled policy is shown read-only, as what the kernel executes.
    console_page.get_by_text("Advanced: Cedar policy language", exact=True).click()
    expect(console_page.get_by_role("heading", name="As policy language")).to_be_visible()
    blocks = console_page.locator("pre.policy-text").all_inner_texts()
    assert any("permit(principal" in block for block in blocks), blocks
    assert any('"endpoint.isolate"' in block for block in blocks), blocks
    # Read-only: the compiled policy is printed, never offered as something to edit here.
    assert console_page.locator("pre.policy-text textarea, pre.policy-text input").count() == 0
    # A limit the tenant counts as one has a meter; one counted per agent says so instead.
    expect(console_page.get_by_text("each agent on its own", exact=False).first).to_be_visible()


def test_a_draft_is_pasted_validated_previewed_and_activated_with_what_changed_named(
    console_page, admin_engine, world
):
    """The whole walk through the stepper: nothing replays on arrival, the preview is the
    step before activation, the confirmation opens on what it found and names the policy it
    replaces, and the reason typed into it is shown on the list afterwards (PL1, PL10)."""
    sign_in_as(console_page, admin_engine, world["admin"])
    previews: list[str] = []
    console_page.on(
        "request",
        lambda request: previews.append(request.url) if request.url.endswith("/preview") else None,
    )
    console_page.goto("/policy")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Policies")
    was_active = str(world["bundle"].bundle_id)
    expect(console_page.get_by_text("the active selection")).to_be_visible()

    paste(
        console_page, document(world, authorization_policies="forbid(principal, action, resource);")
    )
    console_page.get_by_role("button", name="Create from JSON").click()
    expect(console_page).to_have_url(re.compile(r"/policy/[0-9a-f-]{36}$"))
    expect(console_page.get_by_text("Draft", exact=True)).to_be_visible()

    console_page.get_by_role("button", name="Validate").click()
    expect(console_page.get_by_text("Validated", exact=True)).to_be_visible()
    stepper = console_page.get_by_role("list", name="Steps to make this policy live")
    expect(stepper.get_by_text("Not previewed")).to_be_visible()
    assert previews == [], previews

    console_page.get_by_label("Replay over").select_option("24h")
    stepper.get_by_role("button", name="Preview the last 24 hours").click()
    expect(console_page.get_by_text(re.compile(r"decisions? considered"))).to_be_visible()
    summary = stepper.get_by_text(re.compile(r"^Previewed over the last 24 hours: "))
    expect(summary).to_be_visible()
    found = summary.inner_text()

    console_page.get_by_role("button", name="Activate", exact=True).click()
    dialog = console_page.get_by_role("dialog")
    expect(dialog).to_be_visible()
    # It opens on what the preview found, then names the policy that stops being the selection.
    expect(dialog.locator(".dialog-body > p").first).to_have_text(found)
    expect(dialog.get_by_text(was_active[:8])).to_be_visible()
    expect(dialog.get_by_text(re.compile(r"stops being"))).to_be_visible()
    clean(console_page, "the activate confirmation")
    confirm = dialog.get_by_role("button", name="Activate")
    expect(confirm).to_be_disabled()
    dialog.get_by_label(re.compile("What changed and why")).fill("Deny everything while we triage")
    confirm.click()
    expect(console_page.get_by_text("Active in this Space")).to_be_visible()

    console_page.goto("/policy")
    rows = console_page.get_by_role("row")
    # `ACTIVE` means "selected by at least one space" since migration 0041, so the bundle
    # this space stopped selecting goes back to Validated and another space may select it.
    expect(rows.filter(has_text=was_active[:8])).to_contain_text("Validated")
    expect(console_page.locator(".policy-note")).to_have_text("Deny everything while we triage")
    assert console_page.evaluate("window.__violations") == []


def test_a_changed_decision_opens_the_record_in_activitys_drawer(
    console_page, admin_engine, world, runtime
):
    pending(runtime, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/policy")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Policies")
    paste(
        console_page, document(world, authorization_policies="forbid(principal, action, resource);")
    )
    console_page.get_by_role("button", name="Create from JSON").click()
    expect(console_page).to_have_url(re.compile(r"/policy/[0-9a-f-]{36}$"))
    console_page.get_by_role("button", name="Validate").click()
    expect(console_page.get_by_text("Validated", exact=True)).to_be_visible()
    console_page.get_by_role("button", name="Preview the last 7 days").click()
    table = console_page.get_by_role("table", name=re.compile("would have made differently"))
    expect(table).to_be_visible()
    link = table.get_by_role("link").first
    # `text_content`, not `inner_text`: the cell is printed in small capitals, and the record's
    # identity is what the address must carry, not how the page happens to letter it.
    record = (link.text_content() or "").strip().lower()
    assert re.fullmatch(r"[0-9a-f]{8}", record), record
    link.click()
    # Activity keeps its drawer in the address, so the link restores it (#333).
    expect(console_page).to_have_url(re.compile(rf"/activity\?open={record}[0-9a-f-]*$"))


def test_the_selection_needs_a_replacement_before_retirement(console_page, admin_engine, world):
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto(f"/policy/{world['bundle'].bundle_id}")
    expect(console_page.get_by_role("heading", level=1)).to_have_text(
        f"Policy version {str(world['bundle'].bundle_id)[:8]}"
    )
    expect(console_page.get_by_role("button", name="Retire")).to_have_count(0)
    expect(
        console_page.get_by_text("Activate a replacement before retiring", exact=False)
    ).to_be_visible()
    expect(console_page.get_by_text("Active", exact=True)).to_be_visible()


def test_an_approver_is_refused_the_policy_pages(console_page, admin_engine, world):
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/policy")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Policies")
    expect(console_page.get_by_text("This is not yours to do.")).to_be_visible()
    assert json.dumps(console_page.evaluate("window.__violations")) == "[]"


@pytest.fixture
def rules_draft(db, world):
    """A draft written as rules, which is what the rules page edits."""
    content = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    return content


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_the_rules_page_is_clean_in_both_schemes_and_at_phone_width(
    console_page, admin_engine, world, rules_draft, scheme
):
    console_page.emulate_media(color_scheme=scheme)
    sign_in_as(console_page, admin_engine, world["admin"])
    path = f"/policy/{rules_draft.bundle_id}/rules"
    audit(console_page, path, "Rules")
    console_page.set_viewport_size({"width": 390, "height": 780})
    audit(console_page, path, "Rules")


def test_a_rule_is_added_from_the_contracts_own_domains_and_the_draft_follows(
    console_page, admin_engine, world, rules_draft
):
    """The walk #273 describes: the selects are the contract's, and the edit writes a draft."""
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto(f"/policy/{rules_draft.bundle_id}/rules")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Rules")
    # The rules of the pack read as sentences under their action, with the effect as a word.
    expect(console_page.get_by_text("endpoint.isolate").first).to_be_visible()
    expect(console_page.get_by_text(re.compile(r"^(Allow|Deny|Review)$")).first).to_be_visible()

    console_page.get_by_label("Rule identifier").fill("deny-controllers")
    console_page.get_by_label("Effect").select_option("DENY")
    console_page.get_by_role("button", name="Add a condition").click()
    # The value select offers the declared domain and nothing else, so an out-of-domain value
    # cannot be chosen at all rather than being refused after the fact.
    values = console_page.get_by_label("Value").locator("option")
    assert [value for value in values.all_text_contents() if value] == [
        "choose a value",
        "domain_controller",
        "server",
        "workstation",
    ]
    console_page.get_by_label("Value").select_option("domain_controller")
    console_page.get_by_role("button", name="Add the rule").click()
    # The address follows the draft the change wrote; the one it replaced is retired.
    expect(console_page).not_to_have_url(re.compile(rf"/policy/{rules_draft.bundle_id}/rules$"))
    expect(console_page).to_have_url(re.compile(r"/policy/[0-9a-f-]{36}/rules$"))
    expect(console_page.get_by_text("deny-controllers")).to_be_visible()
    # The pack already denies a domain controller, so the new rule reads as a second sentence
    # saying the same thing: rules of one action and one effect combine with or.
    sentences = console_page.get_by_text(
        re.compile(r"Deny isolating an endpoint when the target is a domain controller")
    )
    expect(sentences.first).to_be_visible()
    assert sentences.count() == 2
    # The replaced draft is retired, so the list folds it behind its count.
    console_page.goto("/policy")
    console_page.get_by_role("button", name=re.compile(r"^Show \d+ retired versions?$")).click()
    expect(console_page).to_have_url(re.compile(r"/policy\?retired=1$"))
    rows = console_page.get_by_role(
        "table", name=re.compile("Retired policy versions")
    ).get_by_role("row")
    expect(rows.filter(has_text=str(rules_draft.bundle_id)[:8])).to_contain_text("Retired")
    assert console_page.evaluate("window.__violations") == []


def test_an_active_bundles_rules_are_read_but_not_changed(
    console_page, admin_engine, world, noted_bundle
):
    sign_in_as(console_page, admin_engine, world["admin"])
    reads: list[str] = []
    console_page.on(
        "request",
        lambda request: (
            reads.append(request.url) if "/api/console/v1/policy" in request.url else None
        ),
    )
    console_page.goto(f"/policy/{noted_bundle.bundle_id}/rules")
    # Wait for the route's own heading before asserting anything, as every other case here
    # does. Without it the five seconds each assertion gets covers the route chunk's first
    # load as well as the read, and two suites side by side on CI can spend them both.
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Rules")
    expect(console_page.get_by_text(re.compile("Only a draft can be changed"))).to_be_visible()
    expect(console_page.get_by_role("button", name="Add the rule")).to_have_count(0)
    # It still reads: the sentences and the compiled policy are there.
    expect(console_page.get_by_text(f"Note: {MARKUP}")).to_be_visible()
    assert console_page.locator("img").count() == 0
    console_page.get_by_text("Advanced: compiled Cedar policy", exact=True).click()
    assert "permit(principal" in console_page.locator("pre.policy-text").first.inner_text()
    # The page is one read, not a chain of them: the rules, the budgets, the form's domains
    # and the compiled text all come from `GET /policy/{id}/rules`. An active bundle asks for
    # no more than a draft does, so neither stalls behind the other's answer.
    assert [url.rsplit("/api/console/v1", 1)[1] for url in reads] == [
        f"/policy/{noted_bundle.bundle_id}/rules"
    ], reads


def test_a_seeded_policy_is_customized_through_a_named_start_and_limit_form(
    console_page, admin_engine, world
):
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/policy")
    console_page.get_by_role("button", name="Customize current protections").click()
    expect(console_page).to_have_url(re.compile(r"/policy/[0-9a-f-]{36}$"))
    expect(console_page.get_by_text("Draft", exact=True)).to_be_visible()
    console_page.get_by_role("link", name="Change the rules").click()
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Rules")
    console_page.get_by_text("Adjust limit", exact=True).first.click()
    console_page.get_by_label("Target limit for principal-autonomous-isolation").fill("7")
    console_page.get_by_role("button", name="Save limit").first.click()
    expect(console_page.get_by_text(re.compile(r"7 autonomous targets per 1 hour"))).to_be_visible()
    console_page.goto("/policy")
    expect(
        console_page.get_by_role("row").filter(has_text=str(world["bundle"].bundle_id)[:8])
    ).to_contain_text("the active selection")


def test_a_group_budget_is_added_from_the_offered_groups_and_its_group_changed_in_place(
    console_page, admin_engine, db, world, rules_draft, owner
):
    """A budget counted for one agent group (#273): the group comes from the ones
    the read offers, the edit writes a successor draft, and a group named with markup reads as
    the characters it is."""
    triage = group(owner, world, name="Tier-1 SOC")
    marked = group(owner, world, name=MARKUP)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto(f"/policy/{rules_draft.bundle_id}/rules")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Rules")
    console_page.get_by_label("Budget identifier").fill("squad-hourly")
    console_page.get_by_label("Counted for").select_option("group")
    # The form's own select, whose name starts with its label: "Counted for" now reads "one
    # agent group", and no budget counted for a group exists yet to have a select of its own.
    groups = console_page.get_by_label(re.compile(r"^Agent group"))
    expect(groups.locator("option")).to_have_text([MARKUP, "Tier-1 SOC"])
    clean(console_page, "the budget form with its group select")
    groups.select_option(label="Tier-1 SOC")
    console_page.get_by_role("button", name="Add the budget").click()
    expect(console_page).not_to_have_url(re.compile(rf"/policy/{rules_draft.bundle_id}/rules$"))
    row = console_page.get_by_role("listitem").filter(has_text="squad-hourly")
    expect(row).to_contain_text("group Tier-1 SOC, endpoint.isolate")
    first = console_page.url
    row.get_by_text("Adjust limit", exact=True).click()
    console_page.get_by_label("Agent group for squad-hourly").select_option(label=MARKUP)
    row.get_by_role("button", name="Save limit").click()
    expect(console_page).not_to_have_url(first)
    expect(console_page.get_by_role("listitem").filter(has_text="squad-hourly")).to_contain_text(
        f"group {MARKUP}, endpoint.isolate"
    )
    assert console_page.locator("img").count() == 0
    assert console_page.evaluate("window.__violations") == []
    made = re.search(r"/policy/([0-9a-f-]{36})/rules$", console_page.url)
    assert made is not None, console_page.url
    limits = {
        rule.rule_id: rule
        for rule in read_bundle(
            db, world["admin"], UUID(made.group(1)), world["clock"]
        ).content.limits
    }
    assert limits["squad-hourly"].scope == "group"
    assert limits["squad-hourly"].group_id == marked != triage


UUID_TEXT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def test_a_rules_file_downloaded_here_becomes_a_draft_there(
    console_page, admin_engine, world, noted_bundle, tmp_path
):
    """C14 and PL9 in Chromium: the file downloads with no record identifier in it, and in a
    second Space, offered the same connector account, it becomes a draft there."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        make_space(conn, tenant, "Customer B")
        offer = (
            "UPDATE execbound.connector_accounts SET offered_tenant_wide=true WHERE tenant_id=:t"
        )
        conn.execute(text(offer), {"t": tenant})
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto(f"/policy/{noted_bundle.bundle_id}")
    expect(console_page.get_by_role("heading", level=1)).to_have_text(
        f"Policy version {str(noted_bundle.bundle_id)[:8]}"
    )
    with console_page.expect_download() as caught:
        console_page.get_by_role("button", name="Download rules").click()
    download = caught.value
    assert download.suggested_filename == f"execbound-rules-{str(noted_bundle.bundle_id)[:8]}.json"
    saved = tmp_path / download.suggested_filename
    download.save_as(saved)
    content = saved.read_text(encoding="utf-8")
    assert UUID_TEXT.search(content) is None
    assert json.loads(content)["rules"]

    console_page.goto("/policy")
    console_page.get_by_role("button", name=re.compile(r"; change space$")).first.click()
    console_page.get_by_role("option", name=re.compile("Customer B")).click()
    # The space is the session's now; read the page afresh in it before choosing the file.
    expect(
        console_page.get_by_role("button", name=re.compile(r"Customer B.*; change space$")).first
    ).to_be_visible()
    console_page.goto("/policy")
    expect(console_page.get_by_role("button", name="Create first policy")).to_be_visible()
    settled(console_page)
    console_page.get_by_label("Rules file (JSON, at most 512 KB)").set_input_files(str(saved))
    create = console_page.get_by_role("button", name="Create draft from file")
    expect(create).to_be_enabled()
    create.click()
    expect(console_page).to_have_url(re.compile(r"/policy/[0-9a-f-]{36}$"))
    expect(console_page.get_by_text("Draft", exact=True)).to_be_visible()
    assert console_page.evaluate("window.__violations") == []
