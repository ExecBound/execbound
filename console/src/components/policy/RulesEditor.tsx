// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { changePolicyRulesMutation } from "../../api/@tanstack/react-query.gen";
import type {
  BudgetView,
  ChangePolicyRulesData,
  ChoiceView,
  Proposed,
  QualifierOption,
  RulesView,
} from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { DescribeRule } from "../assistant/DescribeRule";
import { Field, Problem } from "../directory/forms";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { PageHeading } from "../ui/PageHeading";
import { EFFECT, policyName, ruleSentence } from "./format";
import { CopyDraft } from "./BundleList";
import "../rule-links.css";

type Body = ChangePolicyRulesData["body"];
type RuleDraft = Body["rules"][number];
type BudgetDraft = NonNullable<Body["budgets"]>[number];
type ConditionDraft = NonNullable<RuleDraft["when"]>[number];
type Operator = ConditionDraft["operator"];

const EFFECTS = ["ALLOW", "DENY", "REVIEW"] as const;
type Scope = BudgetDraft["scope"];
type Qualified = Exclude<Scope, "principal" | "tenant">;
type Qualifier = Pick<BudgetDraft, "group_id" | "account_id" | "space_id">;
const SCOPES: readonly Scope[] = ["principal", "tenant", "group", "account", "space"];
/** What each qualified scope names: the select's label, the "Counted for" words, and the
 *  read's own list of what it may name, which is everything the write accepts. */
const QUALIFIED: Record<Qualified, { word: string; counted: string; options: (view: RulesView) => QualifierOption[] }> = {
  group: { word: "Agent group", counted: "one agent group", options: (view) => view.qualifiers.groups },
  account: { word: "Connector account", counted: "one connector account", options: (view) => view.qualifiers.accounts },
  space: { word: "Space", counted: "one space", options: (view) => view.qualifiers.spaces },
};

function qualified(scope: Scope | undefined): Qualified | undefined {
  return scope === "group" || scope === "account" || scope === "space" ? scope : undefined;
}

/** The one qualifier a scope carries, and nothing for a scope that names none, so the write
 *  states exactly the budget the person means and the model's pairing rule never has to. */
function qualify(scope: Scope, value: string): Qualifier {
  switch (scope) {
    case "group":
      return { group_id: value };
    case "account":
      return { account_id: value };
    case "space":
      return { space_id: value };
    default:
      return {};
  }
}

function qualifierOf(budget: BudgetView): string {
  return budget.group_id ?? budget.account_id ?? budget.space_id ?? "";
}
const OPERATOR_WORD: Record<Operator, string> = {
  is: "is",
  is_not: "is not",
  in: "is one of",
  at_least: "is at least",
  at_most: "is at most",
};

/** The ruleset as it stands, as the write states it. Derived from the view at the moment of
 *  an edit, never kept beside it, so the page cannot act on a ruleset the server has moved on
 *  from. Each budget keeps its scope and the group, account or space it names. A budget the
 *  form has no field for (a selector, or several actions), or one counted for a group,
 *  account or space the read no longer offers, makes the whole draft read-only instead, so
 *  this is never asked to state one. */
function stated(view: RulesView): Body {
  return {
    rules: view.groups.flatMap((group) =>
      group.rules.map((rule) => ({
        id: rule.id,
        action: rule.action,
        effect: rule.effect,
        when: rule.when.map((condition) => ({
          kind: condition.kind === "argument" ? ("argument" as const) : ("fact" as const),
          name: condition.name,
          operator: condition.operator as Operator,
          values: condition.values,
        })),
        quorum: rule.quorum,
        note: rule.note,
      })),
    ),
    budgets: view.budgets.map((budget) => {
      const scope = SCOPES.find((word) => word === budget.scope) ?? "principal";
      return {
        rule_id: budget.rule_id,
        action: budget.action,
        scope,
        ...qualify(scope, qualifierOf(budget)),
        window_seconds: budget.window_seconds,
        max_targets: budget.max_targets,
        budget: budget.budget === "total" ? ("total" as const) : ("autonomous" as const),
        on_exceed: budget.on_exceed === "DENY" ? ("DENY" as const) : ("REQUIRE_APPROVAL" as const),
      };
    }),
  };
}

/**
 * `focus` is a rule or budget id a link named, such as a denial's rule in the drawer (#678).
 * It is compared by value and marks that item `aria-current`, scrolled into view once; it never
 * becomes an id, a class or a fragment, and an id the page does not hold marks nothing.
 */
export function RulesEditor({ view, focus }: { view: RulesView; focus?: string }) {
  const queryClient = useQueryClient();
  const page = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focus === undefined) return;
    const found = page.current?.querySelector<HTMLElement>('[aria-current="true"]');
    // jsdom has no scrollIntoView; a browser always does.
    if (typeof found?.scrollIntoView === "function") found.scrollIntoView({ block: "center" });
  }, [focus]);
  const navigate = useNavigate();
  const change = useServerMutation({
    ...changePolicyRulesMutation(),
    onSuccess: (next) => {
      toast("Rules changed. The draft that was replaced is retired.");
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listPolicy" }] });
      void navigate({
        to: "/policy/$bundleId/rules",
        params: { bundleId: next.bundle_id },
        replace: true,
      });
    },
  });
  // A budget the form cannot express would be dropped by any edit, and one counted for a
  // qualifier the read no longer offers would be refused by every save (#678), so nothing is
  // editable while one is there; the page names it and sends the person to the JSON.
  const unexpressible = view.budgets.filter((budget) => !budget.editable);
  const editable = view.editable && unexpressible.length === 0;
  const apply = (body: Body) => {
    change.mutate({ path: { bundle_id: view.bundle_id }, body });
  };
  // A rule the assistant drafted from a sentence (#330, version 2). It is a proposal: it
  // fills the form below and becomes policy only when the form is submitted.
  const [proposed, setProposed] = useState<Proposed | undefined>(undefined);
  const [editing, setEditing] = useState<RuleDraft | undefined>(undefined);
  return (
    <div ref={page}>
      <PageHeading
        title="Rules"
        lead="What this draft allows, denies and sends to a person, written as rules rather than as policy language. Every change writes a new draft and retires this one, so each state of the rules stays in the tenant's history."
      />
      <p className="meta">
        <Link to="/policy/$bundleId" params={{ bundleId: view.bundle_id }}>
          Back to {policyName(view.bundle_id)}
        </Link>
      </p>
      {!view.written_as_rules ? (
        <EmptyState title="This bundle was not written as rules.">
          Its policy cannot be safely translated into this form. Open its detail to copy the complete configuration or convert a recognized demonstration policy.
        </EmptyState>
      ) : (
        <>
          {!editable ? (
            <p className="note" role="status">
              {view.state === "DRAFT" && unexpressible.length > 0
                ? `This draft carries a budget this form cannot express (${unexpressible
                    .map((budget) => budget.rule_id)
                    .join(", ")}). It is read here; change it as JSON so nothing is dropped.`
                : "Only a draft can be changed. Copy this bundle to a new draft to edit its rules."}
            </p>
          ) : null}
          {view.state !== "DRAFT" ? <CopyDraft bundleId={view.bundle_id} formAvailable={view.written_as_rules} /> : null}
          <Problem error={change.error} />
          <RuleGroups view={view} editable={editable} pending={change.isPending} apply={apply} onEdit={setEditing} focus={focus} />
          {editable ? (
            <>
              <DescribeRule
                bundleId={view.bundle_id}
                editable={editable}
                onProposed={setProposed}
              />
              <AddRule
                key={editing?.id ?? proposed?.rule.id ?? "blank"}
                view={view}
                pending={change.isPending}
                apply={apply}
                proposed={proposed}
                editing={editing}
                onCancel={() => { setEditing(undefined); }}
              />
            </>
          ) : null}
          <Budgets view={view} editable={editable} pending={change.isPending} apply={apply} focus={focus} />
          <details><summary>Advanced: compiled Cedar policy</summary>
          <Card title="As policy language">
            <p className="muted">
              The compiled bundle, read-only. It is what the kernel executes; the rules above
              are its source.
            </p>
            <pre className="policy-text">{view.compiled.authorization_policies}</pre>
            {view.compiled.approval_policies.trim() === "" ? null : (
              <pre className="policy-text">{view.compiled.approval_policies}</pre>
            )}
          </Card>
          </details>
        </>
      )}
    </div>
  );
}

interface Applier {
  focus?: string;
  editable: boolean;
  pending: boolean;
  apply: (body: Body) => void;
}

function RuleGroups({ view, editable, pending, apply, onEdit, focus }: { view: RulesView; onEdit: (rule: RuleDraft) => void } & Applier) {
  const empty = view.groups.every((group) => group.rules.length === 0);
  return (
    <>
      {empty ? (
        <EmptyState title="This draft has no rule yet.">
          An action with no allow rule is refused, so nothing happens until one is written.
        </EmptyState>
      ) : null}
      {view.groups.map((group) => (
        <Card key={group.action} title={group.label} aside={<span className="mono faint">{group.action}</span>}>
          {group.rules.length === 0 ? (
            <p className="muted">No rule about this action, so it is refused.</p>
          ) : (
            <ul className="policy-rules">
              {group.rules.map((rule) => {
                const effect = EFFECT[rule.effect];
                return (
                  <li
                    key={rule.id}
                    aria-current={rule.id === focus ? "true" : undefined}
                    className={rule.id === focus ? "rule-focus" : undefined}
                  >
                    <span className="badges">
                      {effect === undefined ? null : <Badge tone={effect.tone}>{effect.word}</Badge>}
                      <span className="mono faint">{rule.id}</span>
                      {editable ? (
                        <><Button size="small" disabled={pending} onClick={() => {
                          const draft = stated(view).rules.find((item) => item.id === rule.id);
                          if (draft !== undefined) onEdit(draft);
                        }}>Edit rule</Button><Button
                          size="small"
                          disabled={pending}
                          onClick={() => {
                            const body = stated(view);
                            apply({
                              ...body,
                              rules: body.rules.filter((item) => item.id !== rule.id),
                            });
                          }}
                        >
                          Remove
                        </Button></>
                      ) : null}
                    </span>
                    <p>{ruleSentence(rule.sentence)}</p>
                    {rule.note === null ? null : <p className="muted">Note: {rule.note}</p>}
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      ))}
    </>
  );
}

function Budgets({ view, editable, pending, apply, focus }: { view: RulesView } & Applier) {
  const [action, setAction] = useState(view.groups[0]?.action ?? "");
  const [ruleId, setRuleId] = useState("");
  const [targets, setTargets] = useState("3");
  const [period, setPeriod] = useState("1");
  const [unit, setUnit] = useState("3600");
  const [scope, setScope] = useState<Scope>("principal");
  const [qualifier, setQualifier] = useState("");
  const kind = qualified(scope);
  const [budget, setBudget] = useState<BudgetDraft["budget"]>("autonomous");
  const [onExceed, setOnExceed] = useState<BudgetDraft["on_exceed"]>("REQUIRE_APPROVAL");
  return (
    <Card title="Budgets">
      <p className="muted">
        How many targets each agent, one agent group, one connector account, one space or the
        whole tenant may reach in a window before the answer changes. A budget over a fact, or
        over several actions at once, is written as JSON.
      </p>
      {view.budgets.length === 0 ? (
        <p className="muted">This draft sets no budget.</p>
      ) : (
        <ul className="plain">
          {view.budgets.map((row) => (
            <li
              key={row.rule_id}
              aria-current={row.rule_id === focus ? "true" : undefined}
              className={row.rule_id === focus ? "rule-focus" : undefined}
            >
              <span className="mono">{row.rule_id}</span>: {row.scope}
              {row.qualifier === null ? "" : ` ${row.qualifier}`}, {row.actions.join(", ")},{" "}
              {row.max_targets} {row.budget} targets per {row.window}, over the ceiling{" "}
              {row.on_exceed === "DENY" ? "denied" : "held for a person"}
              {editable ? <BudgetControl view={view} original={row} pending={pending} apply={apply} /> : null}
              {editable ? (
                <>
                  {" "}
                  <Button
                    size="small"
                    disabled={pending}
                    onClick={() => {
                      const body = stated(view);
                      apply({
                        ...body,
                        budgets: (body.budgets ?? []).filter(
                          (item) => item.rule_id !== row.rule_id,
                        ),
                      });
                    }}
                  >
                    Remove
                  </Button>
                </>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {editable ? (
        <>
          <div className="filters">
            <Field label="Budget identifier">
              <input
                value={ruleId}
                maxLength={80}
                onChange={(event) => {
                  setRuleId(event.target.value);
                }}
              />
            </Field>
            <Field label="Action">
              <select
                value={action}
                onChange={(event) => {
                  setAction(event.target.value);
                }}
              >
                {view.groups.map((group) => (
                  <option key={group.action} value={group.action}>
                    {group.action}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Counted for">
              <select
                value={scope}
                onChange={(event) => {
                  const next = SCOPES.find((word) => word === event.target.value) ?? "principal";
                  const named = qualified(next);
                  setScope(next);
                  setQualifier(named === undefined ? "" : (QUALIFIED[named].options(view)[0]?.id ?? ""));
                }}
              >
                <option value="principal">each agent</option>
                <option value="tenant">the whole tenant</option>
                {/* A qualified scope is offered only where the read names something for it. */}
                {(["group", "account", "space"] as const)
                  .filter((word) => QUALIFIED[word].options(view).length > 0)
                  .map((word) => (
                    <option key={word} value={word}>
                      {QUALIFIED[word].counted}
                    </option>
                  ))}
              </select>
            </Field>
            {kind === undefined ? null : (
              <Field label={QUALIFIED[kind].word}>
                <select
                  value={qualifier}
                  onChange={(event) => {
                    setQualifier(event.target.value);
                  }}
                >
                  {QUALIFIED[kind].options(view).map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </Field>
            )}
            <Field label="Targets">
              <input
                type="number"
                min={1}
                value={targets}
                onChange={(event) => {
                  setTargets(event.target.value);
                }}
              />
            </Field>
            <Field label="Time window">
              <input
                type="number"
                min={1}
                value={period}
                onChange={(event) => {
                  setPeriod(event.target.value);
                }}
              />
            </Field>
            <Field label="Window unit"><select value={unit} onChange={(event) => { setUnit(event.target.value); }}><option value="60">minutes</option><option value="3600">hours</option><option value="86400">days</option></select></Field>
            <Field label="Counting">
              <select
                value={budget}
                onChange={(event) => {
                  setBudget(event.target.value === "total" ? "total" : "autonomous");
                }}
              >
                <option value="autonomous">what no person approved</option>
                <option value="total">everything</option>
              </select>
            </Field>
            <Field label="Over the ceiling">
              <select
                value={onExceed}
                onChange={(event) => {
                  setOnExceed(event.target.value === "DENY" ? "DENY" : "REQUIRE_APPROVAL");
                }}
              >
                <option value="REQUIRE_APPROVAL">hold it for a person</option>
                <option value="DENY">deny it</option>
              </select>
            </Field>
          </div>
          <div className="policy-actions">
            <Button
              disabled={pending || ruleId.trim() === "" || action === "" || (kind !== undefined && qualifier === "") || !Number.isInteger(Number(targets)) || Number(targets) < 1 || !Number.isInteger(Number(period)) || Number(period) < 1}
              onClick={() => {
                const body = stated(view);
                apply({
                  ...body,
                  budgets: [
                    ...(body.budgets ?? []),
                    {
                      rule_id: ruleId.trim(),
                      action,
                      scope,
                      ...qualify(scope, qualifier),
                      window_seconds: Number(period) * Number(unit),
                      max_targets: Number(targets),
                      budget,
                      on_exceed: onExceed,
                    },
                  ],
                });
              }}
            >
              Add the budget
            </Button>
          </div>
        </>
      ) : null}
    </Card>
  );
}

const BLANK: ConditionDraft = { kind: "fact", name: "", operator: "is", values: [] };

function BudgetControl({ view, original, pending, apply }: { view: RulesView; original: BudgetView; pending: boolean; apply: (body: Body) => void }) {
  const id = original.rule_id;
  const [targets, setTargets] = useState(String(original.max_targets));
  const initialUnit = original.window_seconds % 3600 === 0 ? 3600 : original.window_seconds % 60 === 0 ? 60 : 1;
  const [unit, setUnit] = useState(String(initialUnit));
  const [period, setPeriod] = useState(String(original.window_seconds / initialUnit));
  const kind = qualified(SCOPES.find((word) => word === original.scope));
  const [qualifier, setQualifier] = useState(qualifierOf(original));
  // Shown only while every budget is editable, and the read marks one counted for a qualifier
  // it no longer offers as not editable (#678), so the qualifier this budget holds is listed.
  const offered = kind === undefined ? [] : QUALIFIED[kind].options(view);
  return <details><summary>Adjust limit</summary><div className="filters">
    {kind === undefined ? null : <Field label={`${QUALIFIED[kind].word} for ${id}`}><select value={qualifier} onChange={(event) => { setQualifier(event.target.value); }}>{offered.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</select></Field>}
    <Field label={`Target limit for ${id}`}><input type="number" min={1} value={targets} onChange={(event) => { setTargets(event.target.value); }} /></Field>
    <Field label={`Time window for ${id}`}><input type="number" min={1} value={period} onChange={(event) => { setPeriod(event.target.value); }} /></Field>
    <Field label={`Window unit for ${id}`}><select value={unit} onChange={(event) => { setUnit(event.target.value); }}><option value="1">seconds</option><option value="60">minutes</option><option value="3600">hours</option><option value="86400">days</option></select></Field>
    <Button disabled={pending || !Number.isInteger(Number(targets)) || Number(targets) < 1 || !Number.isInteger(Number(period)) || Number(period) < 1} onClick={() => {
      const body = stated(view);
      apply({ ...body, budgets: body.budgets?.map((row) => row.rule_id === id ? { ...row, ...(kind === undefined ? {} : qualify(kind, qualifier)), max_targets: Number(targets), window_seconds: Number(period) * Number(unit) } : row) });
    }}>Save limit</Button>
  </div></details>;
}

function AddRule({
  view,
  pending,
  apply,
  proposed,
  editing,
  onCancel,
}: {
  view: RulesView;
  pending: boolean;
  apply: (body: Body) => void;
  /** A rule the assistant drafted, which fills this form and changes nothing else (#330). */
  proposed?: Proposed;
  editing?: RuleDraft;
  onCancel: () => void;
}) {
  // A proposal is this form's initial state and nothing more: the caller gives the component
  // a key of the turn it came from, so a new proposal is a new form rather than a reset run
  // inside an effect, and every field stays the person's to edit before they add the rule.
  const seed = editing ?? proposed?.rule;
  const [action, setAction] = useState(seed?.action ?? view.fields[0]?.action ?? "");
  const [id, setId] = useState(seed?.id ?? "");
  const [effect, setEffect] = useState<RuleDraft["effect"]>(
    EFFECTS.find((word) => word === seed?.effect) ?? "ALLOW",
  );
  const [quorum, setQuorum] = useState(
    seed?.quorum === undefined || seed.quorum === null
      ? ""
      : String(seed.quorum),
  );
  const [note, setNote] = useState(seed?.note ?? "");
  const [when, setWhen] = useState<ConditionDraft[]>(
    (seed?.when ?? []).map((condition) => ({
      kind: condition.kind === "argument" ? ("argument" as const) : ("fact" as const),
      name: condition.name,
      operator: condition.operator as Operator,
      values: condition.values,
    })),
  );
  const choices = view.fields.find((field) => field.action === action)?.choices ?? [];
  const ready = id.trim() !== "" && action !== "" && when.every((row) => row.name !== "" && row.values.length > 0);
  return (
    <Card title={editing ? "Edit rule" : "Add a rule"}>
      <p className="muted">
        A deny rule wins whenever its conditions hold. A review rule adds a person&rsquo;s
        decision when no deny holds. An allow rule is required for anything to happen, and an
        action with no allow rule is refused. Rules of the same action and effect combine with
        or; the conditions inside one rule with and; order never matters.
      </p>
      <div className="filters">
        <Field label="Rule identifier">
          <input
            value={id}
            maxLength={80}
            onChange={(event) => {
              setId(event.target.value);
            }}
          />
        </Field>
        <Field label="Action">
          <select
            value={action}
            onChange={(event) => {
              setAction(event.target.value);
              setWhen([]);
            }}
          >
            {view.fields.map((field) => (
              <option key={field.action} value={field.action}>
                {field.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Effect">
          <select
            value={effect}
            onChange={(event) => {
              const next = EFFECTS.find((word) => word === event.target.value) ?? "ALLOW";
              setEffect(next);
              if (next !== "REVIEW") setQuorum("");
            }}
          >
            <option value="ALLOW">Allow</option>
            <option value="DENY">Deny</option>
            <option value="REVIEW">Review</option>
          </select>
        </Field>
        {effect === "REVIEW" ? (
          <Field label="Approvers" hint="Two to five, or blank for one.">
            <select
              value={quorum}
              onChange={(event) => {
                setQuorum(event.target.value);
              }}
            >
              <option value="">one</option>
              {[2, 3, 4, 5].map((count) => (
                <option key={count} value={String(count)}>
                  {count}
                </option>
              ))}
            </select>
          </Field>
        ) : null}
      </div>
      <ul className="plain">
        {when.map((condition, index) => (
          <li key={index}>
            <ConditionRow
              choices={choices}
              condition={condition}
              onChange={(next) => {
                setWhen(when.map((row, at) => (at === index ? next : row)));
              }}
              onRemove={() => {
                setWhen(when.filter((_, at) => at !== index));
              }}
            />
          </li>
        ))}
      </ul>
      <Field label="Note" hint="Why the rule is there. Shown on this page and compiled into nothing.">
        <input
          value={note}
          maxLength={200}
          onChange={(event) => {
            setNote(event.target.value);
          }}
        />
      </Field>
      <div className="policy-actions">
        <Button
          disabled={when.length >= 8 || choices.length === 0}
          onClick={() => {
            setWhen([...when, { ...BLANK, name: choices[0]?.name ?? "", kind: choices[0]?.kind === "argument" ? "argument" : "fact" }]);
          }}
        >
          Add a condition
        </Button>
        <Button
          variant="primary"
          disabled={pending || !ready}
          onClick={() => {
            const body = stated(view);
            const rule = { id: id.trim(), action, effect, when,
              quorum: quorum === "" ? null : Number(quorum),
              note: note.trim() === "" ? null : note.trim() };
            apply({
              ...body,
              rules: editing ? body.rules.map((item) => item.id === editing.id ? rule : item) : [
                ...body.rules,
                rule,
              ],
            });
          }}
        >
          {editing ? "Save rule" : "Add the rule"}
        </Button>
        {editing ? <Button onClick={onCancel}>Cancel editing</Button> : null}
      </div>
    </Card>
  );
}

/** One condition: what it names, the operator its type admits, and a value from its domain. */
function ConditionRow({
  choices,
  condition,
  onChange,
  onRemove,
}: {
  choices: ChoiceView[];
  condition: ConditionDraft;
  onChange: (next: ConditionDraft) => void;
  onRemove: () => void;
}) {
  const choice = choices.find((item) => item.name === condition.name);
  const operators = (choice?.operators ?? ["is"]) as Operator[];
  return (
    <div className="filters">
      <Field label="Fact or argument">
        <select
          value={condition.name}
          onChange={(event) => {
            const next = choices.find((item) => item.name === event.target.value);
            onChange({
              kind: next?.kind === "argument" ? "argument" : "fact",
              name: event.target.value,
              operator: "is",
              values: [],
            });
          }}
        >
          {choices.map((item) => (
            <option key={`${item.kind}:${item.name}`} value={item.name}>
              {item.name}
              {item.kind === "argument" ? " (argument)" : ""}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Operator">
        <select
          value={condition.operator}
          onChange={(event) => {
            const next = operators.find((word) => word === event.target.value) ?? "is";
            onChange({ ...condition, operator: next, values: [] });
          }}
        >
          {operators.map((word) => (
            <option key={word} value={word}>
              {OPERATOR_WORD[word]}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Value">
        <ValueControl
          choice={choice}
          condition={condition}
          onChange={(values) => {
            onChange({ ...condition, values });
          }}
        />
      </Field>
      <Button size="small" onClick={onRemove}>
        Remove
      </Button>
    </div>
  );
}

function ValueControl({
  choice,
  condition,
  onChange,
}: {
  choice: ChoiceView | undefined;
  condition: ConditionDraft;
  onChange: (values: ConditionDraft["values"]) => void;
}) {
  if (choice === undefined) return <input disabled value="" />;
  if (choice.cedar_type === "Long") {
    return (
      <input
        type="number"
        min={choice.minimum ?? undefined}
        max={choice.maximum ?? undefined}
        value={condition.values.length > 0 ? String(condition.values[0]) : ""}
        onChange={(event) => {
          onChange(event.target.value === "" ? [] : [Number(event.target.value)]);
        }}
      />
    );
  }
  const many = condition.operator === "in";
  return (
    <select
      multiple={many}
      value={condition.values.map(String)}
      onChange={(event) => {
        const picked = many
          ? [...event.target.selectedOptions].map((option) => option.value)
          : [event.target.value];
        onChange(
          choice.cedar_type === "Boolean" ? picked.map((value) => value === "true") : picked,
        );
      }}
    >
      {!many ? <option value="">choose a value</option> : null}
      {choice.values.map((value) => (
        <option key={String(value)} value={String(value)}>
          {String(value)}
        </option>
      ))}
    </select>
  );
}
