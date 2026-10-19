# SPDX-License-Identifier: AGPL-3.0-only
"""Local fixtures and operator administration. Nothing here is an HTTP endpoint."""

import argparse
import json
import os
import sys
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_hex
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

from execbound import install as installer
from execbound import quickstart as first_run
from execbound import schedule
from execbound.audit import append_event
from execbound.command_help import WORKSPACE_CREDENTIAL_HELP, describe_common
from execbound.connection import connect_args, local_database_url, local_databases
from execbound.contracts import PRODUCTION_CATALOG
from execbound.db import UnsafeDatabaseRole
from execbound.identity import new_token
from execbound.operations import PRODUCTION_ACTIONS
from execbound.plugins import (
    PLUGIN_API_VERSION,
    Command,
    CommandError,
    PluginError,
    database_refusal,
    load_command_plugins,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from execbound.identity import Identity
    from execbound.policy.models import BundleContent, Ruleset
    from execbound.signals.models import SignalMapping


def seed_demo(owner_url: str, output: Path) -> None:
    parsed = local_database_url(owner_url, databases=local_databases(), username="execbound_owner")
    output.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(parsed, hide_parameters=True, connect_args=connect_args(parsed))
    demo: dict[str, Any] = {"tenants": []}
    # Exclusive creation protects existing tokens; no sensitive token is printed.
    try:
        with output.open("x", encoding="utf-8") as handle:
            try:
                with engine.begin() as conn:
                    for label in ("Demo North", "Demo South"):
                        tenant_id, credential_id = uuid4(), uuid4()
                        conn.execute(
                            text("SELECT set_config('execbound.tenant_id', :tenant, true)"),
                            {"tenant": str(tenant_id)},
                        )
                        conn.execute(
                            text(
                                "INSERT INTO execbound.tenants(tenant_id, name) "
                                "VALUES (:tenant, :name)"
                            ),
                            {"tenant": tenant_id, "name": label},
                        )
                        space_id = uuid4()
                        conn.execute(
                            text(
                                "INSERT INTO execbound.spaces "
                                "(tenant_id, space_id, name, created_at, created_by) "
                                "VALUES (:t, :s, 'Default', now(), :t)"
                            ),
                            {"t": tenant_id, "s": space_id},
                        )
                        actors = {}
                        for kind in ("AGENT", "HUMAN_APPROVER", "ADMIN"):
                            principal_id = uuid4()
                            actors[kind] = principal_id
                            conn.execute(
                                text(
                                    "INSERT INTO execbound.principals "
                                    "(tenant_id, principal_id, kind, space_id) "
                                    "VALUES (:t, :p, :k, :s)"
                                ),
                                {
                                    "t": tenant_id,
                                    "p": principal_id,
                                    "k": kind,
                                    "s": space_id if kind == "AGENT" else None,
                                },
                            )
                            if kind == "HUMAN_APPROVER":
                                conn.execute(
                                    text(
                                        "INSERT INTO execbound.space_members "
                                        "(tenant_id, space_id, principal_id, role, "
                                        "assigned_at) "
                                        "VALUES (:t, :s, :p, 'HUMAN_APPROVER', now())"
                                    ),
                                    {"t": tenant_id, "s": space_id, "p": principal_id},
                                )
                        token, digest = new_token(tenant_id, credential_id)
                        expires_at = datetime.now(UTC) + timedelta(hours=1)
                        conn.execute(
                            text("""
                            INSERT INTO execbound.credentials
                                (tenant_id, credential_id, principal_id, token_hash, expires_at)
                            VALUES (:t, :c, :p, :h, :e)
                        """),
                            {
                                "t": tenant_id,
                                "c": credential_id,
                                "p": actors["AGENT"],
                                "h": digest,
                                "e": expires_at,
                            },
                        )
                        append_event(
                            conn,
                            tenant_id,
                            actors["ADMIN"],
                            "demo.provisioned",
                            {"principal_count": 3},
                        )
                        demo["tenants"].append(
                            {
                                "name": label,
                                "tenant_id": str(tenant_id),
                                "agent_token": token,
                                "expires_at": expires_at.isoformat(),
                            }
                        )
                    json.dump(demo, handle, indent=2)
                    handle.write("\n")
            except BaseException:
                # Close before unlinking on Windows; only our newly created file is removed.
                handle.close()
                output.unlink()
                raise
    finally:
        engine.dispose()


def audit_export(
    tenant: UUID,
    credential_file: Path,
    output: Path,
    checkpoint: Path,
    database: str | None = None,
) -> None:
    from execbound.connection import with_database_name
    from execbound.db import Database
    from execbound.identity import authenticate
    from execbound.replay.export import ExportError, export_history, publish_export
    from execbound.replay.runner import read_bounded

    db = None
    try:
        token = read_bounded(credential_file, 162).decode("ascii").rstrip("\r\n")
        # `--database` names a restored copy on the server DATABASE_URL already points at,
        # so only the name changes and no connection string is rendered with its password.
        # A refused name raises inside this handler, so it becomes the generic ExportError.
        url = os.environ["DATABASE_URL"]
        # `is not None`, not truthiness: an explicitly empty name is a refusal, not a
        # request for the configured database.
        db = Database(with_database_name(url, database) if database is not None else url)
        identity = authenticate(db, token)
        if identity.tenant_id != tenant or identity.kind != "ADMIN":
            raise ValueError("Invalid export scope")
        history = export_history(db, identity)
        publish_export(db, identity, history, output=output, checkpoint=checkpoint)
        return
    except UnsafeDatabaseRole:
        # The runtime check's own refusal, whose messages are all fixed strings with no value
        # in them: the command then says what the emergency stop's commands say
        # (`plugins.database_refusal`), instead of the generic export failure.
        raise
    # Raise the generic error outside the handler; nested exceptions may hold private data.
    except Exception:  # nosec B110 - the generic error is raised outside this handler
        pass
    finally:
        if db is not None:
            db.close()
    raise ExportError()


OWNER_COMMANDS = frozenset(
    {
        "tenant-create",
        "principal-create",
        "credential-issue",
        "person-invite",
        "credential-list",
        "credential-revoke",
        "approver-assign",
        "approver-unassign",
        "failures",
        "group-create",
        "group-assign",
        "group-unassign",
        "group-list",
        "space-create",
        "space-rename",
        "space-archive",
        "space-unarchive",
        "space-assign",
        "space-unassign",
        "space-list",
        "executor-key-register",
        "executor-key-rotate",
        "executor-key-revoke",
        "executor-key-compromise",
        "executor-key-list",
        "account-create",
        "account-list",
        "mapping-create",
        "mapping-list",
        "target-create",
        "resource-create",
        "resource-list",
        "ruleset-compile",
    }
)
BUNDLE_COMMANDS = frozenset(
    {
        "bundle-create",
        "bundle-validate",
        "bundle-activate",
        "bundle-retire",
        "bundle-list",
        "bundle-preview",
    }
)
STOP_COMMANDS = frozenset(
    {
        "tenant-stop",
        "tenant-resume",
        "tenant-status",
        "tenant-mode",
        "tenant-approval-deadline",
        "tenant-assistant",
        "observe-report",
        "rotation-readiness",
    }
)
RECOVER_COMMAND = "recover"
AUDIT_VERIFY_COMMAND = "audit-verify"
RECONCILE_COMMAND = "reconcile"
NOTIFY_COMMANDS = frozenset({"notify", "notifications"})
EXPORT_COMMANDS = frozenset({"export-events", "export-status", "export-resume"})
CONTEXT_COMMANDS = frozenset(
    {"context-source-create", "context-source-deactivate", "context-import"}
)
# Security signal producers (#478): owner commands, because a source bears authority.
SIGNAL_COMMANDS = frozenset(
    {"signal-source-create", "signal-source-rotate", "signal-source-revoke", "signal-source-list"}
)
# The teammate invitations cron (#487): a tenant-agnostic drain, no identity, no tenant.
INVITATIONS_COMMAND = "invitations-run"
WEEKLY_SUMMARY_COMMAND = "weekly-summary-run"
# The three commands a Community installation is made of: two of them are here.
INIT_COMMAND = "init"
QUICKSTART_COMMAND = "quickstart"
JOBS_COMMAND = "jobs"
# Lists the plugins EXECBOUND_PLUGINS enables; reaches no database and no network.
PLUGINS_COMMAND = "plugins"
MAX_BUNDLE_FILE_BYTES = 512 * 1024


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)


def _key_material(args: argparse.Namespace) -> str:
    if args.public_key_file is not None:
        from execbound.administration import AdministrationError

        # A key file normally ends in a newline, which the Ed25519 shape check would
        # otherwise refuse; stripped here rather than by every algorithm's own validator.
        try:
            return str(args.public_key_file.read_text(encoding="ascii")).strip()
        except (OSError, UnicodeError):
            raise AdministrationError("INVALID_KEY") from None
    return str(args.public_key)


def load_bundle_file(path: Path, tenant: UUID) -> "BundleContent":
    """Parse an operator bundle file; report field locations, never the field values."""
    from pydantic import ValidationError

    from execbound.policy.models import BundleContent
    from execbound.replay.runner import read_bounded
    from execbound.requests import _unique_object

    try:
        raw = read_bounded(path, MAX_BUNDLE_FILE_BYTES)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except Exception:
        raise ValueError(
            "Bundle file is not a readable JSON document within the size limit"
        ) from None
    if type(value) is not dict:
        raise ValueError("Bundle file must contain a JSON object")
    value.setdefault("tenant_id", str(tenant))
    value.setdefault("bundle_id", str(uuid4()))
    if value["tenant_id"] != str(tenant):
        raise ValueError("Bundle tenant_id must match --tenant")
    try:
        return BundleContent.model_validate_json(json.dumps(value))
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors(include_input=False, include_url=False)
        )
        raise ValueError(f"Bundle file is invalid: {problems}") from None


class RulesetFileError(ValueError):
    """A refusal the operator is shown verbatim: field locations, never field values.

    Separate from the bare `ValueError` the owner dispatch reports as an unavailable
    connection, because the whole use of this message is to say which rule was wrong.
    """


def load_ruleset_file(path: Path) -> "Ruleset":
    """Parse an operator ruleset file; report field locations, never the field values.

    The reading is `rulesets.parse_ruleset_document`'s, which the console's rules-file import
    shares; this keeps the command's own three messages.
    """
    from execbound.policy.rulesets import (
        MAX_RULESET_FILE_BYTES,
        RulesetDocumentError,
        parse_ruleset_document,
    )
    from execbound.replay.runner import read_bounded

    unreadable = "Ruleset file is not a readable JSON document within the size limit"
    try:
        raw = read_bounded(path, MAX_RULESET_FILE_BYTES)
    except Exception:
        raise RulesetFileError(unreadable) from None
    try:
        return parse_ruleset_document(raw)
    except RulesetDocumentError as exc:
        if exc.reason == "not-object":
            raise RulesetFileError("Ruleset file must contain a JSON object") from None
        if exc.reason == "invalid":
            raise RulesetFileError(f"Ruleset file is invalid: {'; '.join(exc.problems)}") from None
        raise RulesetFileError(unreadable) from None


def load_signal_mappings_file(path: Path) -> "tuple[SignalMapping, ...]":
    """Parse a signal mappings file; report field locations, never the field values."""
    from pydantic import TypeAdapter, ValidationError

    from execbound.replay.runner import read_bounded
    from execbound.requests import _unique_object
    from execbound.signals.models import SignalMapping

    try:
        raw = read_bounded(path, MAX_BUNDLE_FILE_BYTES)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except Exception:
        raise RulesetFileError(
            "Signal mappings file is not a readable JSON document within the size limit"
        ) from None
    if type(value) is not list:
        raise RulesetFileError("Signal mappings file must contain a JSON array")
    try:
        return TypeAdapter(tuple[SignalMapping, ...]).validate_json(json.dumps(value))
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors(include_input=False, include_url=False)
        )
        raise RulesetFileError(f"Signal mappings file is invalid: {problems}") from None


def compile_ruleset_file(engine: "Engine", args: Any) -> str:
    """Write the bundle content a ruleset means, over the tenant's own active mappings.

    An installation that holds only the image could not author a first policy. The rules
    editor needs an active bundle to know which actions it may speak about, and the bundle
    document the policy pages and `bundle-create` accept carries a Cedar schema and two
    policy sets, which nothing in the image would write. The compiler that turns rules into
    those components existed but was reachable only from the development harness, so the
    first bundle of every deployment came from a checkout.

    This is that compiler as a command. It writes a file and nothing else: no bundle row, no
    activation, no audit event, because it changes nothing to audit. The safety story is
    unchanged and is not this command's to keep — `bundle-validate` and `bundle-activate`
    recompile the ruleset the content carries and refuse content that disagrees with it, so
    a hand-edited bundle document is refused whether this wrote its first draft or not.

    The mappings are the tenant's active ones rather than a bundle's, which is what makes a
    first bundle possible; a rule naming an action no mapping serves is refused by the
    compiler with its field location. `--ref` chooses among them, because two contracts that
    disagree on one entity, or one action under two contracts, cannot share a bundle; a ref
    that is another name for its action carries that action, so rules name the action and the
    ref stays the operator's. `--signal-mappings` is carried, never compiled, as
    `context_settings` is.
    """
    from pydantic import ValidationError

    from execbound import administration as admin
    from execbound.policy.models import MappingRef
    from execbound.policy.rulesets import RulesetError, ruleset_bundle

    ruleset = load_ruleset_file(args.input)
    active = [summary for summary in admin.list_mappings(engine, args.tenant) if summary.active]
    if args.ref:
        named = {summary.operation_ref: summary for summary in active}
        if any(ref not in named for ref in args.ref):
            raise RulesetFileError("A --ref names no active operation mapping")
        active = [named[ref] for ref in dict.fromkeys(args.ref)]
    mappings = tuple(
        MappingRef(
            operation_ref=summary.operation_ref,
            account_id=summary.account_id,
            mapping_version=summary.mapping_version,
            schema_version="action.v1",
            context_contract_version=summary.context_contract_version,
            # A ref that is another name for its action says which action it serves, so the
            # rules compile about that action; the store holds it to the row's.
            action=summary.action if summary.action != summary.operation_ref else None,
        )
        for summary in active
    )
    signal_mappings = (
        load_signal_mappings_file(args.signal_mappings) if args.signal_mappings else None
    )
    if not mappings:
        raise RulesetFileError("The tenant has no active operation mapping; create one first")
    bundle_id = uuid4()
    try:
        content = ruleset_bundle(
            ruleset,
            tenant_id=args.tenant,
            bundle_id=bundle_id,
            mappings=mappings,
            context_settings=ruleset.context,
            signal_mappings=signal_mappings,
        )
    except RulesetError as exc:
        # A mapping that cannot be compiled beside the others is one the operator can leave
        # out, and without --ref every active mapping was taken.
        hint = (
            "; choose the mappings to compile over with --ref"
            if not args.ref and exc.location.startswith("mappings.")
            else ""
        )
        raise RulesetFileError(f"Ruleset is invalid: {exc} ({exc.location}){hint}") from None
    except ValidationError as exc:
        # The assembled bundle refused what was carried into it, a set of signal mappings
        # say: field locations and messages, never the values, as the file loaders report.
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors(include_input=False, include_url=False)
        )
        raise RulesetFileError(f"The compiled bundle is invalid: {problems}") from None
    document = content.model_dump(mode="json")
    try:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        raise RulesetFileError("The bundle file was not written") from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return _json(
        {
            "bundle_id": bundle_id,
            "bundle_file": str(args.output),
            "mappings": [summary.operation_ref for summary in mappings],
            "rules": len(ruleset.rules),
            "budgets": len(ruleset.budgets),
            "signal_mappings": len(signal_mappings or ()),
        }
    )


def run_owner_command(args: Any) -> str:
    """Owner-connection administration; every change is audited under --actor."""
    from execbound import administration as admin

    engine = admin.owner_engine(os.environ["MIGRATION_DATABASE_URL"])
    try:
        if args.command == "tenant-create":
            return _json(
                {"tenant_id": admin.create_tenant(engine, args.name, tenant_id=args.tenant)}
            )
        if args.command == "principal-create":
            principal = admin.create_principal(
                engine, args.tenant, args.kind, args.actor, space=args.space
            )
            return _json({"principal_id": principal, "kind": args.kind})
        if args.command == "credential-issue":
            issued = admin.issue_credential(
                engine,
                args.tenant,
                args.principal,
                args.actor,
                lifetime=timedelta(hours=args.lifetime_hours),
                output=args.output,
            )
            return _json(
                {
                    "credential_id": issued.credential_id,
                    "principal_id": issued.principal_id,
                    "kind": issued.kind,
                    "expires_at": issued.expires_at.isoformat(),
                    "token_file": str(issued.output),
                }
            )
        if args.command == "person-invite":
            invited = admin.invite_person(
                engine,
                args.tenant,
                args.email,
                args.kind,
                label=args.label,
                actor=args.actor,
                lifetime=timedelta(hours=args.lifetime_hours),
                origin=args.origin,
                output=args.output,
            )
            return _json(
                {
                    "principal_id": invited.principal_id,
                    "kind": invited.kind,
                    "email": invited.email,
                    "created": invited.created,
                    "reset_id": invited.reset_id,
                    "expires_at": invited.expires_at.isoformat(),
                    "open": invited.address,
                    "code_file": str(invited.output),
                }
            )
        if args.command == "credential-list":
            return _json([vars(item) for item in admin.list_credentials(engine, args.tenant)])
        if args.command == "credential-revoke":
            admin.revoke_credential(engine, args.tenant, args.credential, args.actor)
            return _json({"credential_id": args.credential, "revoked": True})
        if args.command == "failures":
            tenant = None if args.unattributed else args.tenant
            if tenant is None and not args.unattributed:
                raise admin.AdministrationError("INVALID_TENANT")
            listed = admin.list_failures(engine, tenant, since=timedelta(hours=args.since_hours))
            return _json([vars(item) for item in listed])
        if args.command == "approver-assign":
            admin.assign_approver(
                engine,
                args.tenant,
                args.approver,
                args.target,
                args.action,
                args.actor,
                space=args.space,
            )
            return _json({"approver_id": args.approver, "assigned": True})
        if args.command == "approver-unassign":
            admin.unassign_approver(
                engine, args.tenant, args.approver, args.target, args.action, args.actor
            )
            return _json({"approver_id": args.approver, "assigned": False})
        if args.command == "group-create":
            group = admin.create_group(engine, args.tenant, args.name, args.actor)
            return _json({"group_id": group})
        if args.command == "group-assign":
            admin.assign_group(engine, args.tenant, args.group, args.principal, args.actor)
            return _json({"group_id": args.group, "principal_id": args.principal, "assigned": True})
        if args.command == "group-unassign":
            admin.unassign_group(engine, args.tenant, args.group, args.principal, args.actor)
            return _json(
                {"group_id": args.group, "principal_id": args.principal, "assigned": False}
            )
        if args.command == "group-list":
            return _json([vars(item) for item in admin.list_groups(engine, args.tenant)])
        # The space commands write the same events with the same payloads as the console,
        # so `execbound space-create` and the console are indistinguishable in the chain.
        if args.command == "space-create":
            space = admin.create_space(
                engine, args.tenant, args.name, args.actor, detail=args.detail
            )
            return _json({"space_id": space, "name": args.name})
        if args.command == "space-rename":
            admin.rename_space(
                engine, args.tenant, args.space, args.name, args.actor, detail=args.detail
            )
            return _json({"space_id": args.space, "name": args.name})
        if args.command == "space-archive":
            admin.archive_space(engine, args.tenant, args.space, args.actor, args.reason)
            return _json({"space_id": args.space, "archived": True})
        if args.command == "space-unarchive":
            admin.unarchive_space(engine, args.tenant, args.space, args.actor, args.reason)
            return _json({"space_id": args.space, "archived": False})
        if args.command == "space-assign":
            admin.assign_space(
                engine, args.tenant, args.space, args.principal, args.role, args.actor
            )
            return _json({"space_id": args.space, "principal_id": args.principal, "assigned": True})
        if args.command == "space-unassign":
            admin.unassign_space(engine, args.tenant, args.space, args.principal, args.actor)
            return _json(
                {"space_id": args.space, "principal_id": args.principal, "assigned": False}
            )
        if args.command == "space-list":
            return _json([vars(item) for item in admin.list_spaces(engine, args.tenant)])
        if args.command == "executor-key-register":
            admin.register_executor_key(
                engine,
                args.tenant,
                args.key_id,
                _key_material(args),
                args.actor,
                algorithm=args.algorithm,
            )
            # Identifiers only: the key the operator supplied is never echoed back.
            return _json({"key_id": args.key_id, "registered": True})
        if args.command == "executor-key-rotate":
            admin.rotate_executor_key(
                engine,
                args.tenant,
                args.key_id,
                args.new_key_id,
                _key_material(args),
                args.actor,
                algorithm=args.algorithm,
            )
            return _json(
                {"key_id": args.new_key_id, "previous_key_id": args.key_id, "rotated": True}
            )
        if args.command == "executor-key-revoke":
            admin.revoke_executor_key(engine, args.tenant, args.key_id, args.actor)
            return _json({"key_id": args.key_id, "revoked": True})
        if args.command == "executor-key-compromise":
            admin.report_executor_key_compromise(engine, args.tenant, args.key_id, args.actor)
            # A separate command, as it is a separate function: cutting a stolen key off
            # is not a retirement with a flag, and an operator reaching for one must not
            # reach the other by omitting an argument.
            return _json({"key_id": args.key_id, "compromised": True})
        if args.command == "executor-key-list":
            return _json([vars(item) for item in admin.list_executor_keys(engine, args.tenant)])
        if args.command == "account-create":
            account = admin.create_account(
                engine,
                args.tenant,
                args.provider,
                args.actor,
                space=args.space,
                account_id=args.account,
            )
            return _json({"account_id": account, "provider": args.provider})
        if args.command == "account-list":
            return _json([vars(item) for item in admin.list_accounts(engine, args.tenant)])
        if args.command == "mapping-create":
            mapping = admin.create_mapping(
                engine,
                args.tenant,
                args.account,
                args.action,
                args.actor,
                operation_ref=args.ref,
                mapping_version=args.mapping_version,
                context_contract_version=args.contract_version,
            )
            return _json(vars(mapping))
        if args.command == "mapping-list":
            return _json([vars(item) for item in admin.list_mappings(engine, args.tenant)])
        if args.command == "target-create":
            return _json(
                {"canonical_target_id": admin.create_target(engine, args.tenant, args.actor)}
            )
        if args.command == "resource-create":
            facts = {
                name: value
                for name, value in (
                    ("role", args.role),
                    ("privilege_class", args.privilege_class),
                    ("environment", args.environment),
                    ("criticality", args.criticality),
                )
                if value is not None
            }
            created = admin.create_resource(
                engine,
                args.tenant,
                args.account,
                args.resource_type,
                args.provider_id,
                args.source,
                args.actor,
                version=args.version,
                target=args.target,
                hostname=args.hostname,
                alias_days=args.alias_days,
                facts=facts or None,
            )
            return _json(
                {
                    "resource_id": created.resource_id,
                    "canonical_target_id": created.canonical_target_id,
                    "aliases": list(created.aliases),
                }
            )
        if args.command == "resource-list":
            return _json(
                [
                    {**vars(item), "aliases": list(item.aliases)}
                    for item in admin.list_resources(engine, args.tenant)
                ]
            )
        if args.command == "ruleset-compile":
            return compile_ruleset_file(engine, args)
        raise admin.AdministrationError("INVALID_COMMAND")
    finally:
        engine.dispose()


def run_context_command(args: Any) -> str:
    """Owner-connection trusted context provisioning; every change is audited under --actor."""
    from execbound import administration as admin
    from execbound import provisioning

    engine = admin.owner_engine(os.environ["MIGRATION_DATABASE_URL"])
    try:
        if args.command == "context-source-create":
            source = provisioning.create_context_source(
                engine, args.tenant, args.account, args.kind, args.writer, args.actor
            )
            return _json(
                {
                    "source_id": source,
                    "account_id": args.account,
                    "kind": args.kind,
                    "allowed_writers": sorted(set(args.writer)),
                }
            )
        if args.command == "context-source-deactivate":
            provisioning.deactivate_context_source(engine, args.tenant, args.source, args.actor)
            return _json({"source_id": args.source, "active": False})
        parsed = provisioning.parse_manifest(provisioning.read_manifest(args.manifest))
        # Created before the import, so a report path that cannot take it is refused with
        # nothing imported. The block takes the file away again if it ends in an exception:
        # a refused import, or a report that could not be written after the import committed.
        report = provisioning.ReportFile(args.report) if args.report is not None else None
        with report if report is not None else nullcontext():
            result = provisioning.import_manifest(
                engine, args.tenant, parsed, args.actor, strict=args.strict
            )
            if report is not None:
                report.write(result)
        return _json(result.summary())
    finally:
        engine.dispose()


def _signal_lifetime(hours: int) -> timedelta:
    """`--hours` as a lifetime; one past what a timedelta holds is refused like any other."""
    from execbound.provisioning import ProvisioningError

    try:
        return timedelta(hours=hours)
    except OverflowError:
        raise ProvisioningError("INVALID_LIFETIME") from None


def run_signal_command(args: Any) -> str:
    """Owner-connection signal source registration; every change is audited under --actor."""
    from execbound import administration as admin
    from execbound import provisioning

    engine = admin.owner_engine(os.environ["MIGRATION_DATABASE_URL"])
    try:
        if args.command == "signal-source-create":
            grant = provisioning.create_signal_source(
                engine,
                args.tenant,
                args.actor,
                label=args.label,
                producer=args.producer,
                version_min=args.version_min,
                version_max=args.version_max,
                capabilities=args.capability or ["resource_compromise.v1"],
                principals=args.principal or (),
                group=args.group,
                space=args.space,
                offered=args.offered,
                input_path=args.input_path,
                attests_liveness=args.attests_liveness,
                lifetime=_signal_lifetime(args.hours),
                output=args.output,
            )
            return _json(
                {
                    "source_id": grant.source_id,
                    "expires_at": grant.expires_at,
                    "output": grant.output,
                }
            )
        if args.command == "signal-source-rotate":
            grant = provisioning.rotate_signal_source(
                engine,
                args.tenant,
                args.source,
                args.actor,
                lifetime=_signal_lifetime(args.hours),
                grace_seconds=args.grace_seconds,
                output=args.output,
            )
            return _json(
                {
                    "source_id": grant.source_id,
                    "expires_at": grant.expires_at,
                    "output": grant.output,
                }
            )
        if args.command == "signal-source-revoke":
            provisioning.revoke_signal_source(engine, args.tenant, args.source, args.actor)
            return _json({"source_id": args.source, "active": False})
        return _json(provisioning.list_signal_sources(engine, args.tenant))
    finally:
        engine.dispose()


def run_bundle_command(args: Any) -> str:
    """Bundle lifecycle as a current ADMIN over the restricted runtime connection."""
    from execbound.db import Database
    from execbound.identity import authenticate
    from execbound.policy.store import (
        PolicyStoreError,
        activate_bundle,
        create_bundle,
        list_bundles,
        retire_bundle,
        validate_bundle,
    )
    from execbound.replay.runner import read_bounded

    content: BundleContent | None = None
    if args.command == "bundle-create":
        content = load_bundle_file(args.input, args.tenant)
    db = Database(os.environ["DATABASE_URL"])
    try:
        token = read_bounded(args.credential_file, 162).decode("ascii").rstrip("\r\n")
        identity = authenticate(db, token)
        if identity.tenant_id != args.tenant or identity.kind != "ADMIN":
            raise PolicyStoreError("INVALID_IDENTITY")
        if args.command == "bundle-list":
            return _json([vars(item) for item in list_bundles(db, identity)])
        if args.command == "bundle-preview":
            from execbound.policy.preview import preview_bundle

            preview = preview_bundle(
                db, identity, args.bundle, window=timedelta(hours=args.window_hours)
            )
            return preview.model_dump_json(indent=2)
        if args.command == "bundle-create":
            assert content is not None
            record = create_bundle(db, identity, content)
        elif args.command == "bundle-validate":
            record = validate_bundle(db, identity, args.bundle)
        elif args.command == "bundle-activate":
            record = activate_bundle(db, identity, args.bundle, reason=args.reason)
        else:
            record = retire_bundle(db, identity, args.bundle)
        return _json(
            {
                "bundle_id": record.content.bundle_id,
                "content_hash": record.content.content_hash,
                "state": record.state,
            }
        )
    finally:
        db.close()


def run_stop_command(args: Any) -> str:
    """Emergency stop control as a current ADMIN over the restricted runtime connection."""
    from execbound.assistant.config import PROVIDER_RETENTION
    from execbound.assistant.turns import AssistantError, set_tenant_switch
    from execbound.db import Database
    from execbound.execution import (
        activate_stop,
        approval_deadline,
        enforcement_mode,
        observe_report,
        release_stop,
        set_approval_deadline,
        set_enforcement_mode,
        stop_status,
    )
    from execbound.execution.models import ExecutionError, StopState
    from execbound.identity import authenticate
    from execbound.replay.runner import read_bounded
    from execbound.resolution.models import SystemClock

    db = Database(os.environ["DATABASE_URL"])
    try:
        token = read_bounded(args.credential_file, 162).decode("ascii").rstrip("\r\n")
        identity = authenticate(db, token)
        if identity.tenant_id != args.tenant or identity.kind != "ADMIN":
            raise ExecutionError("INVALID_IDENTITY")
        stop: StopState | None
        if args.command == "rotation-readiness":
            from execbound.rotation import rotation_readiness

            readiness = rotation_readiness(db, identity)
            return _json(
                {
                    "tenant_id": args.tenant,
                    "unsettled": [
                        {"account_id": account, "count": count}
                        for account, count in readiness.unsettled
                    ],
                    "latest_approval_expiry": readiness.latest_approval_expiry,
                    "latest_session_expiry": readiness.latest_session_expiry,
                }
            )
        if args.command == "tenant-mode":
            change = set_enforcement_mode(db, identity, args.set, args.reason)
            return _json(
                {
                    "tenant_id": args.tenant,
                    "enforcement_mode": change.mode,
                    "previous": change.previous,
                }
            )
        if args.command == "tenant-assistant":
            try:
                switch = set_tenant_switch(
                    db, identity, args.set == "on", args.reason, SystemClock()
                )
            except AssistantError as exc:
                # The CLI's refusal path is the execution error's: the code, exit 2.
                raise ExecutionError(exc.code) from None
            return _json(
                {
                    "tenant_id": args.tenant,
                    "assistant_enabled": switch.enabled,
                    "previous": switch.previous,
                    "provider_retention": PROVIDER_RETENTION,
                }
            )
        if args.command == "tenant-approval-deadline":
            # Seconds within the bounds, or off; anything else the setting refuses.
            raw = args.set.strip().lower()
            if raw != "off" and not raw.isdigit():
                raise ExecutionError("INVALID_DEADLINE")
            wanted = None if raw == "off" else int(raw)
            deadline = set_approval_deadline(db, identity, wanted, args.reason)
            return _json(
                {
                    "tenant_id": args.tenant,
                    "approval_deadline_seconds": deadline.seconds,
                    "previous": deadline.previous,
                }
            )
        if args.command == "observe-report":
            return _json(observe_report(db, identity, since_hours=args.since_hours))
        if args.command == "tenant-stop":
            stop = activate_stop(db, identity, args.reason)
        elif args.command == "tenant-resume":
            stop = release_stop(db, identity, args.reason)
        else:
            stop = stop_status(db, identity)
        return _json(
            {
                "tenant_id": args.tenant,
                "stopped": args.command != "tenant-resume" and stop is not None,
                "stop_id": stop.stop_id if stop else None,
                "stopped_at": stop.stopped_at if stop else None,
                "stopped_by": stop.stopped_by if stop else None,
                "reason": stop.reason if stop else None,
                "enforcement_mode": enforcement_mode(db, identity),
                "approval_deadline_seconds": approval_deadline(db, identity),
            }
        )
    finally:
        db.close()


def run_audit_verify_command(args: Any) -> dict[str, Any]:
    """Every workspace's audit chain, or the named ones, as the runtime role with no credential.

    The retained heads are read before the database is, so a checkpoint the command cannot use
    stops the run before it reads anything.
    """
    from execbound.audit_verify import checkpoint_files, load_checkpoints, verify_all
    from execbound.db import Database
    from execbound.jobs import BUDGET_SECONDS

    paths = list(args.checkpoint or [])
    if args.checkpoints is not None:
        paths += checkpoint_files(args.checkpoints)
    checkpoints = load_checkpoints(paths)
    # A pool of one: the pass is sequential and must not compete with the gateway.
    db = Database(os.environ["DATABASE_URL"], pool_size=1, max_overflow=0)
    try:
        return verify_all(
            db,
            checkpoints,
            tenants=args.tenant,
            budget_seconds=BUDGET_SECONDS if args.budget_seconds is None else args.budget_seconds,
        )
    finally:
        db.close()


def run_recover_command(args: Any) -> str:
    """Bounded recovery through the private configuration's runtime, which also reaches sample
    accounts.

    Three modes: one tenant as its current ADMIN (`--tenant` and `--credential-file`), each
    tenant in a tenant-to-token map as its ADMIN (`--tenants-file`), or, for the schedule,
    every active workspace as its scheduler principal with no credential (`--all-tenants`,
    #503).
    """
    from execbound.assistant.turns import retire_turns
    from execbound.db import Database
    from execbound.execution.models import ExecutionError
    from execbound.identity import authenticate
    from execbound.jobs import for_each_tenant, read_tenants_file
    from execbound.recovery_run import recover
    from execbound.replay.runner import read_bounded
    from execbound.resolution.models import SystemClock
    from execbound.surfaces.configuration import load_runtime

    clock = SystemClock()
    # A pool of one: the run is sequential and must not compete with the gateway.
    db = Database(os.environ["DATABASE_URL"], pool_size=1, max_overflow=0)
    runtime = None
    try:
        runtime, _ = load_runtime(Path(os.environ["EXECBOUND_RUNTIME_CONFIG"]), db)
        source = runtime

        def run(identity: "Identity") -> dict[str, Any]:
            settled = vars(
                recover(
                    db,
                    identity,
                    source,
                    limit=args.limit,
                    grace=timedelta(seconds=args.grace_seconds),
                    cancel_unattempted=args.cancel_unattempted,
                )
            )
            # An administrator's run retires the assistant's due turns itself, because it
            # runs as the tenant's ADMIN (#330); the schedule's `--all-tenants` pass retires
            # through `recover_scheduled` instead. Recovery has committed its own work by
            # now, so a refusal here costs this tenant's report and never its settlements.
            return {**settled, "assistant_turns_retired": retire_turns(db, identity, clock)}

        if args.all_tenants:
            from execbound.jobs import BUDGET_SECONDS, every_workspace
            from execbound.recovery_run import recover_scheduled

            grace = timedelta(seconds=args.grace_seconds)
            return _json(
                every_workspace(
                    db,
                    lambda tenant: recover_scheduled(
                        db,
                        tenant,
                        source,
                        destinations=source.notifications,
                        limit=args.limit,
                        grace=grace,
                        clock=clock,
                    ),
                    command="recover",
                    budget_seconds=(
                        BUDGET_SECONDS if args.budget_seconds is None else args.budget_seconds
                    ),
                )
            )
        if args.tenants_file is not None:
            # Every tenant in the map gets its own run; one tenant's refusal is its
            # outcome, not the exit code, so the next tenant still gets swept.
            tokens = read_tenants_file(args.tenants_file)
            return _json({"tenants": for_each_tenant(db, tokens, run, command="recover")})
        token = read_bounded(args.credential_file, 162).decode("ascii").rstrip("\r\n")
        identity = authenticate(db, token)
        if identity.tenant_id != args.tenant or identity.kind != "ADMIN":
            raise ExecutionError("INVALID_IDENTITY")
        return _json(run(identity))
    finally:
        if runtime is not None:
            for connector in runtime.connectors.values():
                connector.close()
        db.close()


def run_invitations_command(args: Any) -> str:
    """The teammate invitations drain (#487): needs no identity and no tenant, because
    `deliver_invitations` reaches every tenant on its own through its one cross-tenant
    definer function. Schedule it as a job of its own rather than chained after another
    command: `execbound.boot` execs its target program with no shell (see its own docstring
    and `_execute`'s `os.execvp`), so a literal `&&` in a start command chains nothing and is
    handed to the first program as extra, unrecognized arguments.
    """
    from execbound.db import Database
    from execbound.invitations import InvitationError, deliver_invitations
    from execbound.surfaces.configuration import load_runtime

    db = Database(os.environ["DATABASE_URL"], pool_size=1, max_overflow=0)
    runtime = None
    try:
        runtime, human = load_runtime(Path(os.environ["EXECBOUND_RUNTIME_CONFIG"]), db)
        if runtime.mail is None:
            raise InvitationError("INVALID_CONFIGURATION")
        counts = deliver_invitations(db, mail=runtime.mail, origin=human.origin, limit=args.limit)
        return _json(counts)
    finally:
        if runtime is not None:
            for connector in runtime.connectors.values():
                connector.close()
        db.close()


def run_weekly_summary_command(args: Any) -> str:
    """The weekly summary (#678): queue this week's messages inside each subscribed workspace,
    then send what is due. Needs no identity and no tenant, as the invitations drain needs
    none, and refuses to start where the runtime configuration's `mail` block has the summary
    off: a deployment that never sends it offers nobody the switch either.
    """
    from execbound.db import Database
    from execbound.surfaces.configuration import load_runtime
    from execbound.weekly_summary import SummaryError, offered, run

    db = Database(os.environ["DATABASE_URL"], pool_size=1, max_overflow=0)
    runtime = None
    try:
        runtime, human = load_runtime(Path(os.environ["EXECBOUND_RUNTIME_CONFIG"]), db)
        if runtime.mail is None or not offered(runtime.mail):
            raise SummaryError("INVALID_CONFIGURATION")
        counts = run(db, mail=runtime.mail, origin=human.origin, limit=args.limit)
        return _json(counts)
    finally:
        if runtime is not None:
            for connector in runtime.connectors.values():
                connector.close()
        db.close()


def run_reconcile_command(args: Any) -> str:
    """Settle one committed or indeterminate operation from provider evidence with a reason."""
    from execbound.db import Database
    from execbound.execution import store
    from execbound.execution.models import ExecutionError
    from execbound.identity import authenticate
    from execbound.provider.gateway import reconcile_operation
    from execbound.replay.runner import read_bounded
    from execbound.resolution.models import SystemClock
    from execbound.surfaces.configuration import load_runtime

    db = Database(os.environ["DATABASE_URL"], pool_size=1, max_overflow=0)
    runtime = None
    try:
        runtime, _ = load_runtime(Path(os.environ["EXECBOUND_RUNTIME_CONFIG"]), db)
        token = read_bounded(args.credential_file, 162).decode("ascii").rstrip("\r\n")
        identity = authenticate(db, token)
        if identity.tenant_id != args.tenant or identity.kind != "ADMIN":
            raise ExecutionError("INVALID_IDENTITY")
        with db.transaction(identity.tenant_id) as conn:
            store.identity_check(conn, identity, SystemClock(), "ADMIN")
            row = store.read(conn, identity.tenant_id, args.execution)
            account = store.frozen(row).intent.account_id
        with runtime.connection(identity.tenant_id, account) as connector:
            if connector is None:
                raise ExecutionError("CONNECTOR_UNAVAILABLE")
            view = reconcile_operation(
                db,
                identity,
                args.execution,
                connector,
                reason=args.reason,
                cancel_if_missing=args.cancel_if_missing,
                verifier=runtime.evidence_verifier(identity.tenant_id, account),
            )
        return _json(view.model_dump(mode="json"))
    finally:
        if runtime is not None:
            for item in runtime.connectors.values():
                item.close()
        db.close()


def run_notify_command(args: Any) -> str:
    """Drain or list approval notifications.

    Listing, and a drain for one tenant or for each tenant in a tenant-to-token map, run as a
    current ADMIN, the way `recover`'s administrator modes do. The schedule's drain
    (`--all-tenants`, #503) holds no credential: it visits every workspace a configured
    destination names, acting with the workspace alone (a `ScheduledActor` that names no
    principal, because the drain writes no event and never makes the scheduler principal). In
    either walk, a workspace that refuses is that workspace's outcome rather than the run's
    exit code.
    """
    from execbound.db import Database
    from execbound.execution.models import ExecutionError
    from execbound.identity import authenticate
    from execbound.jobs import for_each_tenant, read_tenants_file
    from execbound.notifications import deliver_pending, list_notifications
    from execbound.replay.runner import read_bounded

    db = Database(os.environ["DATABASE_URL"], pool_size=1, max_overflow=0)
    runtime = None
    try:
        if args.command == "notify":
            from execbound.surfaces.configuration import load_runtime

            runtime, _ = load_runtime(Path(os.environ["EXECBOUND_RUNTIME_CONFIG"]), db)
            destinations, approval_url, mail = (
                runtime.notifications,
                runtime.approval_url or "",
                runtime.mail,
            )
            links = runtime.plugins.approval_links
            # A loaded plugin's own approval address, for every mode alike (#496).
            approval_path = None if links is None else links.path

            def drain(identity: "Identity") -> dict[str, Any]:
                return dict(
                    deliver_pending(
                        db,
                        identity,
                        destinations,
                        limit=args.limit,
                        approval_url=approval_url,
                        mail=mail,
                        approval_path=approval_path,
                    )
                )

            if args.all_tenants:
                from execbound.jobs import every_workspace
                from execbound.notifications import destination_tenants, notify_scheduled

                return _json(
                    every_workspace(
                        db,
                        lambda tenant: notify_scheduled(
                            db,
                            tenant,
                            destinations,
                            limit=args.limit,
                            approval_url=approval_url,
                            mail=mail,
                            approval_path=approval_path,
                        ),
                        command="notify",
                        tenants=destination_tenants(destinations),
                    )
                )
            if args.tenants_file is not None:
                tokens = read_tenants_file(args.tenants_file)
                return _json({"tenants": for_each_tenant(db, tokens, drain, command="notify")})
        token = read_bounded(args.credential_file, 162).decode("ascii").rstrip("\r\n")
        identity = authenticate(db, token)
        if identity.tenant_id != args.tenant or identity.kind != "ADMIN":
            raise ExecutionError("INVALID_IDENTITY")
        if args.command == "notifications":
            listed = list_notifications(db, identity, state=args.state)
            return _json([vars(item) for item in listed])
        return _json(drain(identity))
    finally:
        if runtime is not None:
            for connector in runtime.connectors.values():
                connector.close()
        db.close()


def run_export_command(args: Any) -> str:
    """Export security events, report cursor status or resume a failed cursor as an ADMIN."""
    from execbound.db import Database
    from execbound.execution.models import ExecutionError
    from execbound.export import export_events, export_status, resume_export
    from execbound.identity import authenticate
    from execbound.replay.runner import read_bounded
    from execbound.surfaces.configuration import load_runtime

    db = Database(os.environ["DATABASE_URL"], pool_size=1, max_overflow=0)
    runtime = None
    try:
        runtime, _ = load_runtime(Path(os.environ["EXECBOUND_RUNTIME_CONFIG"]), db)
        token = read_bounded(args.credential_file, 162).decode("ascii").rstrip("\r\n")
        identity = authenticate(db, token)
        if identity.tenant_id != args.tenant or identity.kind != "ADMIN":
            raise ExecutionError("INVALID_IDENTITY")
        if args.command == "export-events":
            return _json(export_events(db, identity, runtime.notifications, limit=args.limit))
        if args.command == "export-resume":
            resume_export(db, identity, args.destination)
        return _json(export_status(db, identity, runtime.notifications))
    finally:
        if runtime is not None:
            for connector in runtime.connectors.values():
                connector.close()
        db.close()


def _check_all_tenants(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """What `recover --all-tenants` and `notify --all-tenants` both refuse before the walk
    starts; `recover`'s own branch checks its budget, grace and cancellation after this.

    A flag another mode reads is refused rather than ignored. A limit outside what every
    workspace's step accepts is refused once here: past this point each workspace would
    refuse it as its own outcome, and the run would exit 0 having done nothing.
    """
    if args.tenant is not None or args.credential_file is not None:
        parser.error("--all-tenants takes no --tenant or --credential-file")
    if not 1 <= args.limit <= 50:
        parser.error("--limit must be 1 to 50")


def _replay_fixture(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Build, re-record or check a replay regression fixture. A refusal names a code and
    never a value or a path, because what it read may be a tenant's private history."""
    from execbound.replay.fixture import FixtureError, run_check, run_rerecord
    from execbound.replay.sanitize import run_build

    try:
        if args.command == "replay-fixture-check":
            fixture, found = run_check(args.fixture)
            if found:
                parser.exit(
                    1, "Replay fixture differs:\n" + "".join(f"  {line}\n" for line in found)
                )
            decisions, candidates = (
                len(fixture.expected.baseline.decisions),
                len(fixture.candidates),
            )
            print(
                f"Replay fixture matches: {decisions} decision{'s' * (decisions != 1)} and "
                f"{candidates} candidate{'s' * (candidates != 1)}. No live operation was performed."
            )
            return
        if args.from_fixture is not None:
            if args.input is not None or args.trusted_head is not None or args.candidate:
                parser.error("--from-fixture takes no --input, --trusted-head or --candidate")
            run_rerecord(args.from_fixture, args.output)
        else:
            if args.input is None or args.trusted_head is None:
                parser.error("replay-fixture needs --input and --trusted-head, or --from-fixture")
            run_build(args.input, args.trusted_head, args.candidate, args.output)
    except FixtureError as refusal:
        if refusal.code == "FIXTURE_UNAVAILABLE":
            parser.exit(2, "Replay fixture unavailable.\n")
        parser.exit(2, f"Replay fixture unavailable: {refusal.code}.\n")
    except Exception:  # An unexpected error may carry a private value; name none.
        parser.exit(2, "Replay fixture unavailable.\n")
    print("Replay fixture created. No live operation was performed.")


def main() -> None:
    from execbound.logging_schema import install as install_logging
    from execbound.logging_schema import log_event

    install_logging()
    command = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
    try:
        _main()
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        level = "WARNING" if code else "INFO"
        log_event("command.completed", level=level, command=command, exit_code=code)
        raise
    log_event("command.completed", command=command, exit_code=0)


def build_parser() -> tuple[argparse.ArgumentParser, Any]:
    """Every core command and its arguments, before a plugin adds its own.

    What `_main` parses with, and what `scripts/cli_reference.py` writes the command-line
    reference from, so the reference and the parser cannot describe different commands."""
    parser = argparse.ArgumentParser(description="ExecBound installation and administration")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser(
        INIT_COMMAND, help="Write a one-host installation into a directory, secrets and all"
    )
    init_parser.add_argument("directory", type=Path, help="An empty directory you own")
    init_parser.add_argument(
        "--image",
        default=os.environ.get("EXECBOUND_IMAGE") or installer.DEFAULT_IMAGE,
        help="The image the compose file runs; a pull reference when a registry publishes one",
    )
    init_parser.add_argument(
        "--port", type=int, default=installer.DEFAULT_PORT, help="Where the gateway listens"
    )
    init_parser.add_argument("--project", default=installer.DEFAULT_PROJECT)
    init_parser.add_argument(
        "--origin", help="The origin people will use; the loopback port by default"
    )
    init_parser.add_argument(
        "--telemetry",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Answer the usage report question without being asked; the default is no, and "
        "nothing sends a report yet",
    )
    quickstart_parser = subparsers.add_parser(
        QUICKSTART_COMMAND,
        help="Take an empty database to a governed decision in one fenced sequence",
    )
    quickstart_parser.add_argument("--name", default=first_run.DEFAULT_NAME, help="The tenant name")
    quickstart_parser.add_argument("--private", type=Path, default=first_run.DEFAULT_PRIVATE)
    quickstart_parser.add_argument("--state", type=Path, default=first_run.DEFAULT_STATE)
    quickstart_parser.add_argument("--providers", type=Path, default=first_run.DEFAULT_PROVIDERS)
    quickstart_parser.add_argument("--gateway", default=first_run.DEFAULT_GATEWAY)
    quickstart_parser.add_argument(
        "--credential-days", type=int, default=first_run.DEFAULT_CREDENTIAL_DAYS
    )
    quickstart_parser.add_argument("--alembic-config", type=Path, default=Path("alembic.ini"))
    jobs_parser = subparsers.add_parser(
        JOBS_COMMAND, help="Run the scheduled jobs on their intervals, one replica at a time"
    )
    jobs_parser.add_argument("--state", type=Path, default=schedule.DEFAULT_STATE)
    jobs_parser.add_argument(
        "--collector",
        type=Path,
        default=schedule.DEFAULT_COLLECTOR,
        help="The directory holding the collector's key and the platform app's credential",
    )
    jobs_parser.add_argument(
        "--checkpoints",
        type=Path,
        default=schedule.DEFAULT_CHECKPOINTS,
        help="The directory of retained audit heads audit-verify places on each chain",
    )
    jobs_parser.add_argument("--limit", type=int, default=50)
    jobs_parser.add_argument(
        "--once", action="store_true", help="One pass over every due job, then exit"
    )
    demo_parser = subparsers.add_parser("seed-demo", help="Create two synthetic tenants")
    demo_parser.add_argument("--output", type=Path, default=Path("local-data/demo.json"))
    validation_parser = subparsers.add_parser(
        "seed-validation", help="Provision a private local demo"
    )
    validation_parser.add_argument("--output", type=Path, required=True)
    validation_parser.add_argument("--seed", default="execbound-validation-v1")
    for service, port in (("gateway", 8100), ("endpoint", 8101), ("identity", 8102)):
        validation_parser.add_argument(f"--{service}-port", type=int, default=port)
    replay_parser = subparsers.add_parser(
        "replay", help="Replay immutable files without live access"
    )
    replay_parser.add_argument("--input", type=Path, required=True)
    replay_parser.add_argument("--trusted-head", type=Path, required=True)
    replay_parser.add_argument("--candidate", type=Path)
    replay_parser.add_argument("--output", type=Path, required=True)
    fixture_parser = subparsers.add_parser(
        "replay-fixture",
        help="Build a sanitized replay regression fixture from an export, or re-record one",
    )
    fixture_parser.add_argument(
        "--input", type=Path, help="The audit export to build from; needed unless --from-fixture"
    )
    fixture_parser.add_argument(
        "--trusted-head",
        type=Path,
        help="The export's independently retained checkpoint; needed with --input",
    )
    fixture_parser.add_argument(
        "--candidate",
        type=Path,
        action="append",
        default=[],
        help="A candidate bundle to record outcomes for; repeat for up to eight, in order",
    )
    fixture_parser.add_argument(
        "--from-fixture",
        type=Path,
        help="Re-record this fixture's expected outcomes instead of building one",
    )
    fixture_parser.add_argument("--output", type=Path, required=True, help="A new file to write")
    fixture_check_parser = subparsers.add_parser(
        "replay-fixture-check",
        help="Replay a regression fixture and compare every decision with its recorded outcome",
    )
    fixture_check_parser.add_argument(
        "--fixture", type=Path, required=True, help="The fixture file to replay and compare"
    )
    reprovision_parser = subparsers.add_parser(
        "mock-reprovision",
        help="Reset one mock target; run inside the mock's own environment",
    )
    reprovision_parser.add_argument("--provider", choices=("endpoint", "identity"), required=True)
    reprovision_parser.add_argument("--tenant", type=UUID, required=True)
    reprovision_parser.add_argument("--target", type=UUID, required=True)
    reprovision_parser.add_argument(
        "--version",
        help="Set this version and touch nothing else; omit to reset to the file's values",
    )
    reprovision_parser.add_argument("--reason", default="")
    export_parser = subparsers.add_parser(
        "audit-export", help="Export one tenant as a current ADMIN"
    )
    export_parser.add_argument("--tenant", type=UUID, required=True)
    export_parser.add_argument("--credential-file", type=Path, required=True)
    export_parser.add_argument("--output", type=Path, required=True)
    export_parser.add_argument("--checkpoint", type=Path)
    export_parser.add_argument(
        "--database", help="Read a restored copy on the same server, by name"
    )
    tenant_parser = subparsers.add_parser(
        "tenant-create", help="Create a tenant with the owner connection"
    )
    tenant_parser.add_argument(
        "--name", required=True, help="The tenant name; two tenants may share a name"
    )
    tenant_parser.add_argument(
        "--tenant",
        type=UUID,
        default=None,
        help="Create it under this id; for a private configuration that already names one",
    )
    principal_parser = subparsers.add_parser(
        "principal-create", help="Create a principal; a tenant's first ADMIN needs no --actor"
    )
    principal_parser.add_argument("--tenant", type=UUID, required=True)
    principal_parser.add_argument(
        "--kind", choices=["AGENT", "HUMAN_APPROVER", "ADMIN"], required=True
    )
    principal_parser.add_argument("--actor", type=UUID, help="Auditing ADMIN principal")
    principal_parser.add_argument(
        "--space",
        type=UUID,
        default=None,
        help="The space that owns an agent, or seats a person; the tenant's only one by default",
    )
    issue_parser = subparsers.add_parser(
        "credential-issue", help="Issue a credential; its token is written once to --output"
    )
    issue_parser.add_argument("--tenant", type=UUID, required=True)
    issue_parser.add_argument(
        "--principal", type=UUID, required=True, help="The principal the credential is issued to"
    )
    issue_parser.add_argument("--actor", type=UUID, required=True)
    issue_parser.add_argument(
        "--lifetime-hours",
        type=int,
        default=8,
        help="The credential's lifetime in hours, bounded to 90 days: at most 2160",
    )
    issue_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="A new file the token is written to once, created exclusively and owner-only "
        "where the platform carries POSIX modes; an existing path is refused",
    )
    invite_person_parser = subparsers.add_parser(
        "person-invite",
        help="Find or create a person by email and write one set-password code to --output",
    )
    invite_person_parser.add_argument("--tenant", type=UUID, required=True)
    invite_person_parser.add_argument(
        "--email",
        required=True,
        help="The person's sign-in address; the person holding it is found, or one is created",
    )
    invite_person_parser.add_argument(
        "--kind", choices=["ADMIN", "HUMAN_APPROVER"], default="ADMIN"
    )
    invite_person_parser.add_argument("--label", help="A name for the person, up to 80 characters")
    invite_person_parser.add_argument(
        "--actor", type=UUID, help="Auditing ADMIN principal; a tenant's first ADMIN needs none"
    )
    invite_person_parser.add_argument(
        "--lifetime-hours",
        type=int,
        default=24,
        help="Hours until the set-password code expires, between 1 and 336",
    )
    invite_person_parser.add_argument(
        "--origin", required=True, help="This deployment's origin, for the address to open"
    )
    invite_person_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="A new file the set-password code is written to once, exactly as "
        "credential-issue writes a token",
    )
    list_parser = subparsers.add_parser("credential-list", help="List a tenant's credentials")
    list_parser.add_argument("--tenant", type=UUID, required=True)
    revoke_parser = subparsers.add_parser("credential-revoke", help="Revoke a live credential")
    revoke_parser.add_argument("--tenant", type=UUID, required=True)
    revoke_parser.add_argument(
        "--credential",
        type=UUID,
        required=True,
        help="The live credential to revoke; the sessions and continuations it backs end at "
        "their next check",
    )
    revoke_parser.add_argument("--actor", type=UUID, required=True)
    for name, help_text, scope_help in (
        (
            "approver-assign",
            "Assign an approver to one canonical target and action",
            {
                "--target": "A known canonical target",
                "--action": "An action in the action catalog; a new action is assignable as "
                "soon as it is released",
            },
        ),
        (
            "approver-unassign",
            "Deactivate one approver assignment",
            {
                "--approver": "The approver of the assignment to deactivate; pending decisions "
                "under that scope then fail their server-side scope check",
                "--target": "The assignment's canonical target",
                "--action": "The assignment's action",
            },
        ),
    ):
        scope_parser = subparsers.add_parser(name, help=help_text)
        scope_parser.add_argument("--tenant", type=UUID, required=True)
        if name == "approver-assign":
            scope_parser.add_argument(
                "--space",
                type=UUID,
                default=None,
                help="The space the scope is held in; the tenant's only one by default",
            )
        scope_parser.add_argument(
            "--approver", type=UUID, required=True, help=scope_help.get("--approver")
        )
        scope_parser.add_argument("--target", type=UUID, required=True, help=scope_help["--target"])
        scope_parser.add_argument(
            "--action",
            choices=sorted(PRODUCTION_ACTIONS.names),
            required=True,
            help=scope_help["--action"],
        )
        scope_parser.add_argument("--actor", type=UUID, required=True)
    group_create_parser = subparsers.add_parser(
        "group-create", help="Create an empty principal group; names are unique per tenant"
    )
    group_create_parser.add_argument("--tenant", type=UUID, required=True)
    group_create_parser.add_argument(
        "--name",
        required=True,
        help="1 to 80 characters after trimming, unique within the tenant; INVALID_NAME when "
        "shaped like a password, key or token",
    )
    group_create_parser.add_argument("--actor", type=UUID, required=True)
    for name, help_text, group_help, member_help in (
        (
            "group-assign",
            "Add an AGENT principal to a group",
            "The group, which must exist; INVALID_GROUP otherwise",
            "An active AGENT principal (INVALID_PRINCIPAL otherwise), in at most 64 groups; a "
            "repeated or 65th membership is INVALID_MEMBERSHIP",
        ),
        (
            "group-unassign",
            "Remove an AGENT principal from a group",
            "The group to remove the principal from",
            "The principal to remove: its later requests stop charging the group while its "
            "earlier rows keep counting; a missing membership is INVALID_MEMBERSHIP",
        ),
    ):
        group_parser = subparsers.add_parser(name, help=help_text)
        group_parser.add_argument("--tenant", type=UUID, required=True)
        group_parser.add_argument("--group", type=UUID, required=True, help=group_help)
        group_parser.add_argument("--principal", type=UUID, required=True, help=member_help)
        group_parser.add_argument("--actor", type=UUID, required=True)
    group_list_parser = subparsers.add_parser("group-list", help="List a tenant's groups")
    group_list_parser.add_argument("--tenant", type=UUID, required=True)
    space_create_parser = subparsers.add_parser(
        "space-create", help="Create a space; names are unique per tenant, case-insensitively"
    )
    space_create_parser.add_argument("--tenant", type=UUID, required=True)
    space_create_parser.add_argument(
        "--name",
        required=True,
        help="1 to 80 characters after trimming, unique within the tenant case-insensitively; "
        "INVALID_NAME when shaped like a password, key or token",
    )
    space_create_parser.add_argument("--detail", default=None, help="A detail line for the space")
    space_create_parser.add_argument("--actor", type=UUID, required=True)
    space_rename_parser = subparsers.add_parser("space-rename", help="Rename a space")
    space_rename_parser.add_argument("--tenant", type=UUID, required=True)
    space_rename_parser.add_argument(
        "--space", type=UUID, required=True, help="The space to rename"
    )
    space_rename_parser.add_argument(
        "--name",
        required=True,
        help="Its new name: 1 to 80 characters after trimming, unique within the tenant "
        "case-insensitively; INVALID_NAME when shaped like a password, key or token",
    )
    space_rename_parser.add_argument("--detail", default=None)
    space_rename_parser.add_argument("--actor", type=UUID, required=True)
    for name, help_text, space_help, why in (
        (
            "space-archive",
            "Stop new work in a space; nothing is deleted and history stays",
            "The space to stop new work in; archiving the tenant's last unarchived one is refused",
            "archived",
        ),
        (
            "space-unarchive",
            "Let a space take work again",
            "The space to let take work again",
            "unarchived",
        ),
    ):
        state_parser = subparsers.add_parser(name, help=help_text)
        state_parser.add_argument("--tenant", type=UUID, required=True)
        state_parser.add_argument("--space", type=UUID, required=True, help=space_help)
        state_parser.add_argument(
            "--reason",
            required=True,
            help=f"Why the space is {why}; a reason shaped like a password, key or token is "
            "refused as INVALID_NAME",
        )
        state_parser.add_argument("--actor", type=UUID, required=True)
    space_assign_parser = subparsers.add_parser(
        "space-assign", help="Give a person a role in a space; the role narrows and never raises"
    )
    space_assign_parser.add_argument("--tenant", type=UUID, required=True)
    space_assign_parser.add_argument(
        "--space", type=UUID, required=True, help="The space to seat the person in"
    )
    space_assign_parser.add_argument(
        "--principal",
        type=UUID,
        required=True,
        help="The person to seat; an assignment that would leave the tenant with no tenant "
        "administrator is refused",
    )
    space_assign_parser.add_argument(
        "--role",
        choices=("ADMIN", "HUMAN_APPROVER"),
        default="HUMAN_APPROVER",
        help="The person's role in the space, which narrows and never raises: ADMIN is refused "
        "for a HUMAN_APPROVER principal",
    )
    space_assign_parser.add_argument("--actor", type=UUID, required=True)
    space_unassign_parser = subparsers.add_parser(
        "space-unassign", help="Remove a membership; the rows it governed keep their space"
    )
    space_unassign_parser.add_argument("--tenant", type=UUID, required=True)
    space_unassign_parser.add_argument(
        "--space", type=UUID, required=True, help="The space to remove the person from"
    )
    space_unassign_parser.add_argument(
        "--principal",
        type=UUID,
        required=True,
        help="The person to remove; the rows the membership governed keep their space",
    )
    space_unassign_parser.add_argument("--actor", type=UUID, required=True)
    space_list_parser = subparsers.add_parser("space-list", help="List a tenant's spaces")
    space_list_parser.add_argument("--tenant", type=UUID, required=True)
    # A new key id is refused on the same terms by registration and by rotation.
    new_key_id = "a taken id, or one shaped like a password, key or token, is INVALID_KEY"
    for name, help_text, key_id_help, whose in (
        (
            "executor-key-register",
            "Register an executor's public key: Ed25519 as 64 hex characters, or ES256 as "
            "PEM, JWK or compressed hex",
            f"A new id for the key; {new_key_id}",
            "The executor's",
        ),
        (
            "executor-key-rotate",
            "Register a new executor key and revoke the previous one",
            "The live key to replace, retired as RETIRED in the same transaction so a proof for "
            "a grant issued while it was current still verifies; an unknown or already revoked "
            "id is INVALID_KEY",
            "The replacement's",
        ),
        (
            "executor-key-revoke",
            "Revoke an executor key; proofs for earlier grants still verify",
            "The live key to retire as RETIRED; a proof for a grant issued while it was current "
            "still verifies. INVALID_STATE while it is the tenant's last live key and a bundle a "
            "space selects declares an external executor; an unknown or already revoked id is "
            "INVALID_KEY",
            None,
        ),
        (
            "executor-key-compromise",
            "Cut off a stolen executor key; it attests nothing, including earlier grants",
            "The key whose private half is in someone else's hands, live or already retired: it "
            "and every other id of the tenant carrying the same public key are recorded "
            "COMPROMISED and attest nothing, earlier grants included, even when no live key is "
            "left; a key already cut off, or an unknown id, is INVALID_KEY",
            None,
        ),
    ):
        executor_parser = subparsers.add_parser(name, help=help_text)
        executor_parser.add_argument("--tenant", type=UUID, required=True)
        executor_parser.add_argument("--key-id", required=True, help=key_id_help)
        if name == "executor-key-rotate":
            executor_parser.add_argument(
                "--new-key-id",
                required=True,
                help=f"A new id for the replacement key, other than --key-id; {new_key_id}",
            )
        if whose is not None:
            source = executor_parser.add_mutually_exclusive_group(required=True)
            source.add_argument(
                "--public-key",
                help=f"{whose} public key in --algorithm's form: Ed25519 as 64 hex characters "
                "(uppercase is normalized); ES256 as an SPKI PEM, a P-256 JSON Web Key or "
                "compressed SEC1 hex. Material already live for the tenant or recorded as "
                "compromised, or that nobody holds the private half of, is INVALID_KEY",
            )
            source.add_argument(
                "--public-key-file",
                type=Path,
                help="A file holding that public key in the same forms, read instead of "
                "--public-key; trailing whitespace such as a final newline is stripped, and an "
                "unreadable file is INVALID_KEY",
            )
            executor_parser.add_argument(
                "--algorithm",
                choices=("ED25519", "ES256"),
                default="ED25519",
                help="The key's signature scheme; a key attests only reports in its own scheme",
            )
        executor_parser.add_argument("--actor", type=UUID, required=True)
    executor_list_parser = subparsers.add_parser(
        "executor-key-list", help="List a tenant's executor keys and their revocations"
    )
    executor_list_parser.add_argument("--tenant", type=UUID, required=True)
    account_parser = subparsers.add_parser(
        "account-create", help="Create a connector account for one provider"
    )
    account_parser.add_argument("--tenant", type=UUID, required=True)
    account_parser.add_argument(
        "--space",
        type=UUID,
        default=None,
        help="The space that owns the account; the tenant's only one by default",
    )
    account_parser.add_argument(
        "--provider",
        choices=sorted({binding.provider for binding in PRODUCTION_ACTIONS.bindings}),
        required=True,
        help="A provider the action catalog binds; the gateway's private configuration names "
        "the account it creates by id",
    )
    account_parser.add_argument("--actor", type=UUID, required=True)
    account_parser.add_argument(
        "--account",
        type=UUID,
        default=None,
        help="Create it under this id; for a private configuration that already names one",
    )
    config_parser = subparsers.add_parser(
        "config-init",
        help="Write a private gateway configuration and both mock accounts files",
    )
    config_parser.add_argument("--output", type=Path, required=True)
    config_parser.add_argument(
        "--origin", required=True, help="the public origin clients and approvers will use"
    )
    config_parser.add_argument("--tenant", type=UUID, required=True)
    config_parser.add_argument("--endpoint-account", type=UUID, required=True)
    config_parser.add_argument("--identity-account", type=UUID, required=True)
    config_parser.add_argument(
        "--endpoint-origin",
        default="http://127.0.0.1:8001",
        help="loopback only; a provider elsewhere must serve HTTPS",
    )
    config_parser.add_argument("--identity-origin", default="http://127.0.0.1:8002")
    for name, help_text in (
        ("account-list", "List a tenant's connector accounts"),
        ("mapping-list", "List a tenant's operation mappings"),
        ("resource-list", "List a tenant's resources with their targets and aliases"),
    ):
        list_parser = subparsers.add_parser(name, help=help_text)
        list_parser.add_argument("--tenant", type=UUID, required=True)
    mapping_parser = subparsers.add_parser(
        "mapping-create",
        help="Bind a catalog action to an account's provider operation under an operation ref",
    )
    mapping_parser.add_argument("--tenant", type=UUID, required=True)
    mapping_parser.add_argument(
        "--account",
        type=UUID,
        required=True,
        help="The active connector account the mapping binds to; INVALID_ACCOUNT otherwise",
    )
    mapping_parser.add_argument(
        "--action",
        choices=sorted(PRODUCTION_ACTIONS.names),
        required=True,
        help="A catalog action bound for the account's provider (INVALID_ACTION otherwise); "
        "the provider operation and schema version come from the catalog, never the caller",
    )
    mapping_parser.add_argument("--ref", help="Operation ref agents use; defaults to the action")
    mapping_parser.add_argument(
        "--mapping-version",
        default="map-v1",
        help="1 to 80 characters, matching the version the bundle's mapping refs name; "
        "INVALID_VERSION otherwise, or when shaped like a password, key or token",
    )
    mapping_parser.add_argument(
        "--contract-version",
        choices=sorted(PRODUCTION_CATALOG.versions),
        help="A context contract version serving the action; defaults to the catalog's",
    )
    mapping_parser.add_argument("--actor", type=UUID, required=True)
    target_parser = subparsers.add_parser("target-create", help="Create a canonical target")
    target_parser.add_argument("--tenant", type=UUID, required=True)
    target_parser.add_argument("--actor", type=UUID, required=True)
    resource_parser = subparsers.add_parser(
        "resource-create",
        help="Register a provider resource with its canonical target and aliases",
    )
    resource_parser.add_argument("--tenant", type=UUID, required=True)
    resource_parser.add_argument(
        "--account",
        type=UUID,
        required=True,
        help="The active connector account the resource belongs to (INVALID_ACCOUNT otherwise); "
        "--source must be an inventory source of the same account",
    )
    resource_parser.add_argument(
        "--resource-type",
        choices=["endpoint", "identity"],
        required=True,
        help="The resource's type, whose contract domains check the optional facts, which can "
        "also arrive later through context-import; only an endpoint takes --hostname",
    )
    resource_parser.add_argument(
        "--provider-id",
        required=True,
        help="The provider's id for the resource, which becomes its provider_id alias for an "
        "agent's selector; INVALID_PROVIDER_ID when the account already holds it for this "
        "type, or when it is shaped like a password, key or token",
    )
    resource_parser.add_argument(
        "--source", type=UUID, required=True, help="The inventory context source that attests it"
    )
    resource_parser.add_argument(
        "--target", type=UUID, help="An existing canonical target; a new one is created otherwise"
    )
    resource_parser.add_argument("--hostname", help="Endpoint hostname alias")
    resource_parser.add_argument(
        "--version",
        default="resource-v1",
        help="The resource's version, 1 to 80 characters; INVALID_VERSION otherwise, or when "
        "shaped like a password, key or token",
    )
    resource_parser.add_argument(
        "--alias-days",
        type=int,
        default=365,
        help="Days the provider_id and hostname aliases stay valid from creation, 1 to 3660; "
        "INVALID_ALIAS otherwise",
    )
    resource_parser.add_argument(
        "--role",
        help="An endpoint's role, one of domain_controller, server or workstation; "
        "INVALID_FACT otherwise, and for an identity",
    )
    resource_parser.add_argument(
        "--privilege-class",
        help="An identity's privilege class, one of privileged, standard or tier0; "
        "INVALID_FACT otherwise, and for an endpoint",
    )
    resource_parser.add_argument(
        "--environment",
        help="The resource's environment, one of development, production or staging; "
        "INVALID_FACT otherwise",
    )
    resource_parser.add_argument(
        "--criticality",
        type=int,
        help="The resource's criticality, 0 to 4; INVALID_FACT otherwise",
    )
    resource_parser.add_argument("--actor", type=UUID, required=True)
    ruleset_parser = subparsers.add_parser(
        "ruleset-compile",
        help="Compile a ruleset file into a bundle document over the tenant's active mappings",
    )
    ruleset_parser.add_argument("--tenant", type=UUID, required=True)
    ruleset_parser.add_argument("--input", type=Path, required=True, help="The ruleset file")
    ruleset_parser.add_argument(
        "--output", type=Path, required=True, help="Bundle document to write; refuses to overwrite"
    )
    ruleset_parser.add_argument(
        "--ref",
        action="append",
        help="Compile over this active mapping only; repeatable. Default: every active mapping",
    )
    ruleset_parser.add_argument(
        "--signal-mappings",
        type=Path,
        help="A JSON array of signal mappings to carry into the bundle (docs/SIGNALS.md)",
    )
    source_parser = subparsers.add_parser(
        "context-source-create", help="Create a trusted context source with its writer labels"
    )
    source_parser.add_argument("--tenant", type=UUID, required=True)
    source_parser.add_argument(
        "--account",
        type=UUID,
        required=True,
        help="The active connector account the source belongs to (INVALID_ACCOUNT otherwise); "
        "its manifests and the resources it attests are that account's",
    )
    source_parser.add_argument(
        "--kind",
        choices=["inventory", "incident"],
        required=True,
        help="What it attests, inventory facts or incidents: a manifest of the other kind is "
        "INVALID_SOURCE, and resource-create takes only an inventory source",
    )
    source_parser.add_argument(
        "--writer", action="append", required=True, help="A writer label; repeat for several"
    )
    source_parser.add_argument("--actor", type=UUID, required=True)
    deactivate_parser = subparsers.add_parser(
        "context-source-deactivate", help="Deactivate a context source; its facts stop resolving"
    )
    deactivate_parser.add_argument("--tenant", type=UUID, required=True)
    deactivate_parser.add_argument(
        "--source",
        type=UUID,
        required=True,
        help="The active source to deactivate; every fact it attests then fails resolution. An "
        "unknown or already inactive source is INVALID_SOURCE",
    )
    deactivate_parser.add_argument("--actor", type=UUID, required=True)
    import_parser = subparsers.add_parser(
        "context-import", help="Import a context manifest of inventory facts or incidents"
    )
    import_parser.add_argument("--tenant", type=UUID, required=True)
    import_parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="An execbound.context-manifest.v1 file an adapter wrote, at most 16 MiB; validated "
        "against the contract catalog and the tenant's sources and applied in one audited "
        "transaction, or refused with nothing written",
    )
    import_parser.add_argument("--actor", type=UUID, required=True)
    import_parser.add_argument(
        "--strict", action="store_true", help="Refuse the manifest when a resource is unknown"
    )
    import_parser.add_argument("--report", type=Path, help="Write per-entry outcomes to a new file")
    signal_parser = subparsers.add_parser(
        "signal-source-create", help="Register a security signal producer; writes its token once"
    )
    signal_parser.add_argument("--tenant", type=UUID, required=True)
    signal_parser.add_argument("--actor", type=UUID, required=True)
    signal_parser.add_argument(
        "--label",
        required=True,
        help="A label for the producer, 1 to 96 characters of letters, digits, space and ._:- "
        "starting with a letter or digit; INVALID_LABEL otherwise, or when shaped like a "
        "password, key or token",
    )
    signal_parser.add_argument("--producer", required=True, help="Name its envelopes carry")
    signal_parser.add_argument(
        "--version-min",
        required=True,
        help="The lowest producer version accepted, as three integers separated by dots and "
        "compared as numbers; INVALID_VERSION otherwise, or when above --version-max",
    )
    signal_parser.add_argument(
        "--version-max",
        required=True,
        help="The highest producer version accepted, in the same form; an envelope from a "
        "version outside the range is refused INCOMPATIBLE_PRODUCER",
    )
    signal_parser.add_argument(
        "--capability", action="append", help="Repeat for several; default resource_compromise.v1"
    )
    signal_scope = signal_parser.add_mutually_exclusive_group(required=True)
    signal_scope.add_argument(
        "--principal", type=UUID, action="append", help="An agent it may vouch for; repeatable"
    )
    signal_scope.add_argument("--group", type=UUID, help="A principal group it may vouch for")
    signal_parser.add_argument(
        "--space",
        type=UUID,
        help="The space that owns the source; the tenant's only one by default, and "
        "INVALID_SPACE when it has several",
    )
    signal_parser.add_argument("--offered", action="store_true", help="Usable by every space")
    signal_parser.add_argument(
        "--input-path",
        choices=["agent_forwarded", "independent"],
        default="independent",
        help="Whether the agent can feed the producer: independent if not, agent_forwarded if "
        "so; a required signal mapping admits only an independent source",
    )
    signal_parser.add_argument(
        "--attests-liveness",
        action="store_true",
        help="Only set when the producer proves it is still observing each subject",
    )
    signal_parser.add_argument(
        "--hours",
        type=int,
        default=720,
        help="The token's lifetime in hours, 1 to 720; INVALID_LIFETIME otherwise",
    )
    signal_parser.add_argument(
        "--output", type=Path, required=True, help="New file for the token; refuses to overwrite"
    )
    signal_rotate = subparsers.add_parser(
        "signal-source-rotate", help="Replace a producer token; the old one keeps a grace window"
    )
    signal_rotate.add_argument("--tenant", type=UUID, required=True)
    signal_rotate.add_argument(
        "--source",
        type=UUID,
        required=True,
        help="The source to give a new token; a revoked source is INVALID_STATE",
    )
    signal_rotate.add_argument("--actor", type=UUID, required=True)
    signal_rotate.add_argument(
        "--hours",
        type=int,
        default=720,
        help="The new token's lifetime in hours, 1 to 720; INVALID_LIFETIME otherwise",
    )
    signal_rotate.add_argument(
        "--grace-seconds",
        type=int,
        default=600,
        help="How long the old token keeps working, 0 to 3600 seconds and never past its own "
        "expiry; INVALID_GRACE otherwise",
    )
    signal_rotate.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New file for the new token, written once and owner-only; refuses to overwrite",
    )
    signal_revoke = subparsers.add_parser(
        "signal-source-revoke", help="Revoke a producer immediately and finally"
    )
    signal_revoke.add_argument("--tenant", type=UUID, required=True)
    signal_revoke.add_argument(
        "--source",
        type=UUID,
        required=True,
        help="The source to revoke, immediately and finally: every token stops, a rotation's "
        "grace included. A source already revoked is INVALID_STATE",
    )
    signal_revoke.add_argument("--actor", type=UUID, required=True)
    signal_list = subparsers.add_parser(
        "signal-source-list", help="List producers with their registration and health"
    )
    signal_list.add_argument("--tenant", type=UUID, required=True)
    invitations_run_parser = subparsers.add_parser(
        INVITATIONS_COMMAND,
        help="Drain due teammate invitations across every tenant; needs no identity",
    )
    invitations_run_parser.add_argument("--limit", type=int, default=50)
    weekly_summary_parser = subparsers.add_parser(
        WEEKLY_SUMMARY_COMMAND,
        help="Queue and send this week's opt-in summaries across every tenant; needs no identity",
    )
    weekly_summary_parser.add_argument(
        "--limit", type=int, default=50, help="At most this many summaries a run, 1 to 50."
    )
    failures_parser = subparsers.add_parser(
        "failures", help="List authentication failure windows for a tenant, or unattributed ones"
    )
    failures_parser.add_argument("--tenant", type=UUID)
    failures_parser.add_argument("--since-hours", type=int, default=24)
    failures_parser.add_argument(
        "--unattributed", action="store_true", help="Rows without a verified tenant or subject"
    )
    # What `--bundle` names in each lifecycle command that takes one.
    bundle_help = {
        "bundle-validate": "The DRAFT bundle to validate",
        "bundle-activate": "A VALIDATED bundle, or one another space selects, to select for the "
        "tenant's first space; the bundle it replaces returns to VALIDATED unless another space "
        "still selects it",
        "bundle-retire": "The bundle to retire; a bundle any space still selects is refused as "
        "INVALID_STATE, so activate a replacement first",
        "bundle-preview": "The candidate bundle to replay; it is never activated",
    }
    for name, help_text in (
        ("bundle-create", "Create DRAFT bundle content from a JSON file"),
        ("bundle-validate", "Validate a DRAFT bundle"),
        (
            "bundle-activate",
            "Activate a bundle for the tenant's first space; the one it replaces returns to "
            "VALIDATED once no space selects it",
        ),
        ("bundle-retire", "Retire a bundle no space selects"),
        ("bundle-list", "List bundle lifecycle states"),
        ("bundle-preview", "Replay a candidate bundle over recent history without activating it"),
    ):
        bundle_parser = subparsers.add_parser(name, help=help_text)
        bundle_parser.add_argument("--tenant", type=UUID, required=True)
        bundle_parser.add_argument("--credential-file", type=Path, required=True)
        if name == "bundle-create":
            bundle_parser.add_argument(
                "--input",
                type=Path,
                required=True,
                help="The JSON bundle file; tenant_id must match --tenant and bundle_id is "
                "generated when omitted",
            )
        elif name != "bundle-list":
            bundle_parser.add_argument("--bundle", type=UUID, required=True, help=bundle_help[name])
        if name == "bundle-activate":
            bundle_parser.add_argument(
                "--reason",
                help="Why this policy is being activated; recorded in the audit event",
            )
        if name == "bundle-preview":
            bundle_parser.add_argument(
                "--window-hours",
                type=int,
                default=24,
                help="Hours of recent history to replay the candidate over, at most 720",
            )
    for name, help_text in (
        ("tenant-stop", "Activate the tenant emergency stop with a required reason"),
        ("tenant-resume", "Release the tenant emergency stop with a required reason"),
        ("tenant-status", "Show the tenant emergency stop and enforcement mode"),
        ("tenant-mode", "Set the tenant enforcement mode (ENFORCE or OBSERVE) with a reason"),
        (
            "tenant-approval-deadline",
            "Set how long a new approval may wait: seconds from 120 to 3600, or off, with a reason",
        ),
        (
            "tenant-assistant",
            "Turn the console assistant on or off for the tenant with a reason; prompts and "
            "answers are kept by the model provider for up to 30 days under its terms",
        ),
        ("observe-report", "Summarize observed decisions from the audit chain"),
        (
            "rotation-readiness",
            "Show unsettled operations and outstanding expiries that still need current keys",
        ),
    ):
        stop_parser = subparsers.add_parser(name, help=help_text)
        stop_parser.add_argument("--tenant", type=UUID, required=True)
        # Every one of these but `tenant-status` takes a workspace administrator; that one
        # reads the stop and the mode, which an administrator narrowed to spaces reads too.
        stop_parser.add_argument(
            "--credential-file",
            type=Path,
            required=True,
            help=None if name == "tenant-status" else WORKSPACE_CREDENTIAL_HELP,
        )
        if name in {
            "tenant-stop",
            "tenant-resume",
            "tenant-mode",
            "tenant-approval-deadline",
            "tenant-assistant",
        }:
            stop_parser.add_argument("--reason", required=True)
        if name == "tenant-assistant":
            stop_parser.add_argument("--set", choices=("on", "off"), required=True)
        if name == "tenant-mode":
            stop_parser.add_argument("--set", choices=("ENFORCE", "OBSERVE"), required=True)
        if name == "tenant-approval-deadline":
            stop_parser.add_argument("--set", required=True, help="seconds (120 to 3600) or off")
        if name == "observe-report":
            stop_parser.add_argument("--since-hours", type=int, default=24)
    recover_parser = subparsers.add_parser(
        "recover", help="Settle committed but unsettled operations from provider evidence"
    )
    recover_parser.add_argument("--tenant", type=UUID)
    recover_parser.add_argument("--credential-file", type=Path)
    recover_parser.add_argument(
        "--tenants-file", type=Path, help="A tenant-to-token map; one run per tenant"
    )
    recover_parser.add_argument(
        "--all-tenants",
        action="store_true",
        help="Every active workspace, as its scheduler principal, with no credential",
    )
    recover_parser.add_argument(
        "--budget-seconds",
        type=int,
        help="With --all-tenants: start no workspace after this many seconds (default 480)",
    )
    recover_parser.add_argument("--limit", type=int, default=50)
    recover_parser.add_argument("--grace-seconds", type=int, default=300)
    recover_parser.add_argument("--cancel-unattempted", action="store_true")
    verify_parser = subparsers.add_parser(
        AUDIT_VERIFY_COMMAND,
        help="Verify each workspace's audit chain to its head and each retained checkpoint on it",
    )
    verify_parser.add_argument(
        "--all-tenants",
        action="store_true",
        help="Every workspace in the directory, inactive ones too, with no credential",
    )
    verify_parser.add_argument(
        "--tenant", type=UUID, action="append", help="One workspace; may be given again"
    )
    verify_parser.add_argument(
        "--checkpoint",
        type=Path,
        action="append",
        help="A retained head that audit-export wrote; may be given again",
    )
    verify_parser.add_argument(
        "--checkpoints", type=Path, help="A directory of retained heads, each *.head.json in it"
    )
    verify_parser.add_argument(
        "--budget-seconds",
        type=int,
        help="Start no workspace after this many seconds (default 480)",
    )
    reconcile_parser = subparsers.add_parser(
        "reconcile",
        help="Settle one committed or indeterminate operation from provider evidence",
    )
    reconcile_parser.add_argument("--tenant", type=UUID, required=True)
    reconcile_parser.add_argument("--credential-file", type=Path, required=True)
    reconcile_parser.add_argument("--execution", type=UUID, required=True)
    reconcile_parser.add_argument("--reason", required=True)
    reconcile_parser.add_argument("--cancel-if-missing", action="store_true")
    notify_parser = subparsers.add_parser(
        "notify", help="Deliver pending approval notifications to the configured destinations"
    )
    notify_parser.add_argument("--tenant", type=UUID)
    notify_parser.add_argument("--credential-file", type=Path)
    notify_parser.add_argument(
        "--tenants-file", type=Path, help="A tenant-to-token map; one drain per tenant"
    )
    notify_parser.add_argument(
        "--all-tenants",
        action="store_true",
        help="Every workspace a destination names, with no credential",
    )
    notify_parser.add_argument("--limit", type=int, default=50)
    notifications_parser = subparsers.add_parser(
        "notifications", help="List approval notifications and their delivery state"
    )
    notifications_parser.add_argument("--tenant", type=UUID, required=True)
    notifications_parser.add_argument("--credential-file", type=Path, required=True)
    notifications_parser.add_argument(
        "--state", choices=["PENDING", "IN_FLIGHT", "DELIVERED", "FAILED"]
    )
    for name, help_text in (
        ("export-events", "Export new audit events and failure summaries to the destinations"),
        ("export-status", "Show export cursor state and lag per destination"),
        ("export-resume", "Resume a failed export cursor from where it stopped"),
    ):
        export_parser = subparsers.add_parser(name, help=help_text)
        export_parser.add_argument("--tenant", type=UUID, required=True)
        export_parser.add_argument("--credential-file", type=Path, required=True)
        if name == "export-events":
            export_parser.add_argument("--limit", type=int, default=100)
        if name == "export-resume":
            export_parser.add_argument("--destination", required=True)
    subparsers.add_parser(
        PLUGINS_COMMAND, help="List the plugins EXECBOUND_PLUGINS enables, and the plugin API"
    )
    describe_common(parser)
    return parser, subparsers


def _main() -> None:
    parser, subparsers = build_parser()
    # A plugin's commands, added after every core command; EXECBOUND_PLUGINS names the
    # plugins, and a plugin that cannot load stops every command (#238). They are registered
    # here, before arguments are even parsed, so EXECBOUND_PLUGINS itself must be set in the
    # real process environment: `.env`, read below, is too late to change which commands
    # exist. Running a plugin command's own `run`, in contrast, happens after `.env` is read,
    # beside core's own owner commands.
    try:
        plugins = load_command_plugins()
    except PluginError as exc:
        parser.exit(2, f"Plugin refused: {exc.code}.\n")
    plugin_commands: dict[str, Command] = {}
    for plugin_command in plugins.commands:
        if plugin_command.name in subparsers.choices:
            parser.exit(2, "Plugin refused: COMMAND_CONFLICT.\n")
        plugin_command.configure(
            subparsers.add_parser(plugin_command.name, help=plugin_command.help)
        )
        plugin_commands[plugin_command.name] = plugin_command
    args = parser.parse_args()
    if args.command == PLUGINS_COMMAND:
        listed = [{"name": p.name, "api_version": p.api_version} for p in plugins.loaded]
        print(_json({"plugin_api": PLUGIN_API_VERSION, "plugins": listed}))
        return
    # This branch must remain before dotenv, database construction or live bootstrap.
    if args.command == "replay":
        from execbound.replay.runner import ReplayFileError, run_replay

        try:
            run_replay(args.input, args.trusted_head, args.output, args.candidate)
        except ReplayFileError:
            parser.exit(2, "Replay files unavailable.\n")
        print("Replay reports created. No live operation was performed.")
        return
    if args.command in {"replay-fixture", "replay-fixture-check"}:
        # Beside `replay` and for the same reason: a fixture is built and checked from files
        # alone, so neither command reads `.env`, builds a database or reaches a provider.
        _replay_fixture(parser, args)
        return
    if args.command == INIT_COMMAND:
        # Beside `config-init` and `replay`, and for the same reason: this writes files and
        # reaches no database and no network. It is also the first command of three that a
        # machine with nothing but Docker runs, so it must not need a `.env` to exist.
        try:
            result = installer.install(
                args.directory,
                image=args.image,
                port=args.port,
                project=args.project,
                origin=args.origin,
                telemetry=installer.ask_telemetry(
                    args.telemetry, input_stream=sys.stdin, output=sys.stdout
                ),
            )
        except installer.InstallError as exc:
            parser.exit(2, f"{exc}.\n")
        installer.report(result)
        return
    if args.command == "config-init":
        from execbound.bootstrap import MOCK_PRECONDITIONS, provider_material, write_private

        # No database and no network: this writes files from identifiers the operator
        # already holds, so it is handled here with `replay` rather than below, where a
        # connection would be built for no reason.
        connectors: list[dict[str, Any]] = []
        accounts: dict[str, list[dict[str, Any]]] = {"mock_crowdstrike": [], "mock_entra": []}
        for provider, account, origin, key_id in (
            (
                "mock_crowdstrike",
                args.endpoint_account,
                args.endpoint_origin,
                "endpoint-journal-v1",
            ),
            ("mock_entra", args.identity_account, args.identity_origin, "identity-journal-v1"),
        ):
            connector, record = provider_material(
                provider, args.tenant, str(account), origin, key_id=key_id
            )
            connectors.append(connector)
            accounts[provider].append(record)
        configuration = {
            "origin": args.origin,
            "active_key_id": "continuation-v1",
            "continuation_keys": {"continuation-v1": token_hex(32)},
            "connectors": connectors,
            "preconditions": [
                {
                    "provider": provider,
                    "provider_operation": operation,
                    "precondition_class": "ENFORCED_BY_PROVIDER",
                }
                for provider, operation in MOCK_PRECONDITIONS
            ],
        }
        try:
            for name, value in (
                ("gateway.json", configuration),
                ("endpoint-accounts.json", accounts["mock_crowdstrike"]),
                ("identity-accounts.json", accounts["mock_entra"]),
            ):
                write_private(args.output, name, value)
        except (FileExistsError, OSError):
            # Never the path's contents and never a partial explanation naming a secret.
            parser.exit(2, "Private configuration was not written.\n")
        # The path, never the contents: these files hold every token the deployment has.
        print(f"Private configuration written to {args.output}. Mount it read-only.")
        return
    # Beside replay and for the same reason: this runs in a mock's own environment, where
    # there is no gateway database to construct and no dotenv to read.
    if args.command == "mock-reprovision":
        from execbound.boot import BootError, reprovision

        try:
            moved = reprovision(
                os.environ,
                args.provider,
                args.tenant,
                args.target,
                version=args.version,
                reason=args.reason,
            )
        except BootError as exc:
            parser.exit(2, f"Mock reprovision refused: {exc}.\n")
        except (OSError, ValueError):
            parser.exit(2, "Mock reprovision refused: the mock store is unavailable.\n")
        print(_json({"target": str(args.target), **moved}))
        return
    load_dotenv()
    if args.command in plugin_commands:
        try:
            print(plugin_commands[args.command].run(args))
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except CommandError as exc:
            parser.exit(2, exc.message.rstrip("\n") + "\n")
        except PluginError as exc:
            parser.exit(2, f"Command refused: {exc.code}.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Command unavailable.\n")
        return
    if args.command == QUICKSTART_COMMAND:
        try:
            first_run.quickstart(
                owner_url=os.environ["MIGRATION_DATABASE_URL"],
                runtime_url=os.environ["DATABASE_URL"],
                private=args.private,
                state=args.state,
                providers=args.providers,
                gateway=args.gateway,
                name=args.name,
                credential_days=args.credential_days,
                alembic_config=args.alembic_config,
                output=sys.stdout,
            )
        except first_run.QuickstartError as exc:
            parser.exit(2, f"Quickstart stopped: {exc}\n")
        except KeyError:
            parser.exit(2, "Quickstart needs MIGRATION_DATABASE_URL and DATABASE_URL.\n")
        except Exception as exc:  # noqa: BLE001 - the type, never a driver's SQL or values
            parser.exit(2, f"Quickstart stopped with {type(exc).__name__}; nothing is printed.\n")
        return
    if args.command == JOBS_COMMAND:
        try:
            config = os.environ.get("EXECBOUND_RUNTIME_CONFIG")
            path = Path(config) if config else None
            outcomes = schedule.serve(
                os.environ["DATABASE_URL"],
                state=args.state,
                collector=args.collector,
                checkpoints=args.checkpoints,
                once=args.once,
                limit=args.limit,
                mail=schedule.mail_configured(path),
                notify=schedule.destinations_configured(path),
                weekly_summary=schedule.weekly_summary_configured(path),
                # Every installation (#355): the synthetic directory holds no credential,
                # so `collect-due` always has something it can open.
                collect=True,
                deliver=schedule.runtime_configured(path),
            )
        except KeyError:
            parser.exit(2, "The jobs service needs DATABASE_URL.\n")
        if args.once:
            print(_json(outcomes))
        return
    if args.command in OWNER_COMMANDS:
        from execbound.administration import AdministrationError

        try:
            print(run_owner_command(args))
        except AdministrationError as exc:
            parser.exit(2, f"Administration refused: {exc.code}.\n")
        except RulesetFileError as exc:
            parser.exit(2, f"{exc}\n")
        except (KeyError, ValueError):
            parser.exit(2, "Owner connection unavailable.\n")
        return
    if args.command in CONTEXT_COMMANDS:
        from execbound.provisioning import ProvisioningError, ReportNotWritten

        try:
            print(run_context_command(args))
        except ReportNotWritten as exc:
            # The import committed, so this is no refusal: print what it did, then what failed.
            print(_json(exc.result.summary()))
            imported = "Provisioning imported the manifest, but the report was not written"
            parser.exit(2, f"{imported}: {exc.code}.\n")
        except ProvisioningError as exc:
            where = f" at entry {exc.entry}" if exc.entry is not None else ""
            parser.exit(2, f"Provisioning refused: {exc.code}{where}.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Owner connection or manifest file unavailable.\n")
        return
    if args.command in SIGNAL_COMMANDS:
        from execbound.provisioning import ProvisioningError

        try:
            print(run_signal_command(args))
        except ProvisioningError as exc:
            parser.exit(2, f"Provisioning refused: {exc.code}.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Owner connection or output file unavailable.\n")
        return
    if args.command in BUNDLE_COMMANDS:
        from execbound.identity import AuthenticationFailed
        from execbound.policy.store import PolicyStoreError

        try:
            print(run_bundle_command(args))
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except PolicyStoreError as exc:
            where = f" at {exc.location}" if exc.location else ""
            parser.exit(2, f"Policy store refused: {exc.code}{where}.\n")
        except AuthenticationFailed:
            parser.exit(2, "Administrator credential refused.\n")
        except ValueError as exc:
            parser.exit(2, f"{exc}\n")
        except (KeyError, OSError):
            parser.exit(2, "Runtime connection or file unavailable.\n")
        return
    if args.command in EXPORT_COMMANDS:
        from execbound.execution.models import ExecutionError
        from execbound.identity import AuthenticationFailed

        try:
            print(run_export_command(args))
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except ExecutionError as exc:
            parser.exit(2, f"Export refused: {exc.code}.\n")
        except AuthenticationFailed:
            parser.exit(2, "Administrator credential refused.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Runtime configuration, connection or file unavailable.\n")
        return
    if args.command == INVITATIONS_COMMAND:
        from sqlalchemy.exc import SQLAlchemyError

        from execbound.invitations import InvitationError

        try:
            print(run_invitations_command(args))
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except InvitationError as exc:
            parser.exit(2, f"Invitations run refused: {exc.code}.\n")
        except SQLAlchemyError:
            parser.exit(2, "Invitations run refused: database error.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Runtime configuration, connection or file unavailable.\n")
        return
    if args.command == WEEKLY_SUMMARY_COMMAND:
        from sqlalchemy.exc import SQLAlchemyError

        from execbound.weekly_summary import SummaryError

        try:
            print(run_weekly_summary_command(args))
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except SummaryError as exc:
            parser.exit(
                2,
                "Weekly summary run refused: "
                + (
                    "the mail block does not turn the weekly summary on"
                    if exc.code == "INVALID_CONFIGURATION"
                    else exc.code
                )
                + ".\n",
            )
        except SQLAlchemyError:
            parser.exit(2, "Weekly summary run refused: database error.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Runtime configuration, connection or file unavailable.\n")
        return
    if args.command in NOTIFY_COMMANDS:
        from sqlalchemy.exc import SQLAlchemyError

        from execbound.execution.models import ExecutionError
        from execbound.identity import AuthenticationFailed
        from execbound.jobs import TenantsFileError

        if args.command == "notify":
            single = args.tenant is not None and args.credential_file is not None
            if [single, args.tenants_file is not None, args.all_tenants].count(True) != 1:
                parser.error(
                    "give --tenants-file, --all-tenants, or both --tenant and --credential-file"
                )
            if args.all_tenants:
                _check_all_tenants(parser, args)
        try:
            print(run_notify_command(args))
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except ExecutionError as exc:
            parser.exit(2, f"Notification command refused: {exc.code}.\n")
        except SQLAlchemyError:
            parser.exit(2, "Notification command refused: database error.\n")
        except AuthenticationFailed:
            parser.exit(2, "Administrator credential refused.\n")
        except TenantsFileError as exc:
            parser.exit(2, f"Notification command refused: {exc}.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Runtime configuration, connection or file unavailable.\n")
        return
    if args.command == AUDIT_VERIFY_COMMAND:
        from sqlalchemy.exc import SQLAlchemyError

        from execbound.audit_verify import AuditVerifyError, failing
        from execbound.execution.models import ExecutionError

        if args.all_tenants == bool(args.tenant):
            parser.error("give --all-tenants or --tenant")
        if args.budget_seconds is not None and not 1 <= args.budget_seconds <= 3600:
            parser.error("--budget-seconds must be 1 to 3600")
        try:
            report = run_audit_verify_command(args)
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except (AuditVerifyError, ExecutionError) as exc:
            # The directory walk's own refusal (`UNSAFE_JOB_POLICY`) among them.
            parser.exit(2, f"Audit verification refused: {exc.code}.\n")
        except SQLAlchemyError:
            parser.exit(2, "Audit verification refused: database error.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Database connection unavailable.\n")
        print(_json(report))
        if failing(report):
            parser.exit(
                1,
                f"Audit verification failed: {report['broken']} chain(s) did not verify and "
                f"{report['failed']} workspace(s) could not be read.\n",
            )
        return
    if args.command == RECOVER_COMMAND:
        from sqlalchemy.exc import SQLAlchemyError

        from execbound.assistant.turns import AssistantError
        from execbound.execution.models import ExecutionError
        from execbound.identity import AuthenticationFailed
        from execbound.jobs import TenantsFileError

        single = args.tenant is not None and args.credential_file is not None
        if [single, args.tenants_file is not None, args.all_tenants].count(True) != 1:
            parser.error(
                "give --tenants-file, --all-tenants, or both --tenant and --credential-file"
            )
        if args.all_tenants:
            _check_all_tenants(parser, args)
            if args.budget_seconds is not None and not 1 <= args.budget_seconds <= 3600:
                parser.error("--budget-seconds must be 1 to 3600")
            if not 60 <= args.grace_seconds <= 86400:
                parser.error("--grace-seconds must be 60 to 86400")
            if args.cancel_unattempted:
                parser.error(
                    "--cancel-unattempted needs an administrator: give --tenant and "
                    "--credential-file"
                )
        elif args.budget_seconds is not None:
            parser.error("--budget-seconds needs --all-tenants")
        try:
            print(run_recover_command(args))
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except ExecutionError as exc:
            parser.exit(2, f"Recovery refused: {exc.code}.\n")
        except AssistantError as exc:
            # An administrator's run retires the assistant's due turns after recovery has
            # committed its own work; a refusal there is this run's exit code, not a traceback.
            parser.exit(2, f"Recovery refused: {exc.code}.\n")
        except SQLAlchemyError:
            parser.exit(2, "Recovery refused: database error.\n")
        except AuthenticationFailed:
            parser.exit(2, "Administrator credential refused.\n")
        except TenantsFileError as exc:
            parser.exit(2, f"Recovery refused: {exc}.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Runtime configuration, connection or file unavailable.\n")
        return
    if args.command == RECONCILE_COMMAND:
        from execbound.execution.models import ExecutionError
        from execbound.identity import AuthenticationFailed

        try:
            print(run_reconcile_command(args))
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except ExecutionError as exc:
            parser.exit(2, f"Reconciliation refused: {exc.code}.\n")
        except AuthenticationFailed:
            parser.exit(2, "Administrator credential refused.\n")
        except (KeyError, OSError, ValueError):
            parser.exit(2, "Runtime configuration, connection or file unavailable.\n")
        return
    if args.command in STOP_COMMANDS:
        from execbound.execution.models import ExecutionError
        from execbound.identity import AuthenticationFailed

        try:
            print(run_stop_command(args))
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except ExecutionError as exc:
            parser.exit(2, f"Emergency stop refused: {exc.code}.\n")
        except AuthenticationFailed:
            parser.exit(2, "Administrator credential refused.\n")
        except (KeyError, OSError):
            parser.exit(2, "Runtime connection or file unavailable.\n")
        return
    if args.command == "seed-validation":
        try:
            # The harness ships only with a development checkout, never in the wheel.
            from execbound_harness.validation_demo import seed_validation
        except ImportError:
            parser.exit(
                2, "The validation harness is not installed; run from a development checkout.\n"
            )
        try:
            seed_validation(
                os.environ["MIGRATION_DATABASE_URL"],
                args.output,
                seed=args.seed,
                gateway_port=args.gateway_port,
                endpoint_port=args.endpoint_port,
                identity_port=args.identity_port,
            )
        except Exception:
            parser.exit(2, "Validation fixtures unavailable.\n")
        print(
            "Private synthetic fixtures created. Credentials are stored only in the new directory."
        )
        return
    if args.command == "audit-export":
        from execbound.replay.export import ExportError

        try:
            audit_export(
                args.tenant,
                args.credential_file,
                args.output,
                args.checkpoint or args.output.with_suffix(".head.json"),
                args.database,
            )
        except UnsafeDatabaseRole as exc:
            parser.exit(2, database_refusal(exc))
        except ExportError:
            parser.exit(2, "History export unavailable.\n")
        print("History export created. Retain its head independently to anchor later verification.")
        return
    if args.command == "seed-demo":
        seed_demo(os.environ["MIGRATION_DATABASE_URL"], args.output)
        print(f"Created synthetic fixtures. Expiring agent tokens saved to {args.output}.")


if __name__ == "__main__":
    main()
