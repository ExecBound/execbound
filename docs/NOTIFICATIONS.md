# Notifications and webhooks

When a request needs approval, ExecBound can tell the people who may decide it: by email, in a Slack or Teams channel, or with a signed webhook to your own system. A notification carries identifiers, labels and a link to the approval's page. It never carries an approve or refuse control: a person decides on the approval page, signed in, where ExecBound can check who they are.

## Destinations

Destinations are part of a deployment's configuration. On the hosted service, [ask us](https://execbound.ai/help.html) to add one for your workspace. On your own deployment, add it to the `notifications` list in the private configuration.

| Kind | What it needs | What arrives |
| --- | --- | --- |
| `email` | `to`, one bare address, and the deployment's mail relay | A plain-text message |
| `slack` | `url`, a Slack app's incoming webhook | A message in the channel with a button to the approval page |
| `teams` | `url`, a Teams workflow started by "When a Teams webhook request is received" | An Adaptive Card in the channel |
| `webhook` | `url` and `secret`, your endpoint and the key its signature is checked with | A signed JSON body |

Every destination also has a `destination_id`, the `tenant_id` of its workspace, and an optional `approvers` list of principal ids: with one, only approvals assigned to one of those people go there. Office 365 connector URLs for Teams are refused, because Microsoft switched those connectors off.

Workspace settings' **Approval readiness** card lists the workspace's destinations and counts only those that carry approval messages, never the security event export, as announcing approvals; when none does and a held request can wait less than ten minutes, it warns that short approvals reach nobody but someone watching Approvals.

### Which messages a destination receives

An optional `messages` list chooses what a destination is sent about each approval:

| Message | What it is |
| --- | --- |
| `pending` | The announcement of a request waiting for a decision. This is the default, and the only message a destination without a `messages` list receives. |
| `closed` | One follow-up when an approval the destination was told of has ended: approved, refused, lapsed or closed without a decision (see Outcomes). |
| `reminder` | One reminder for a request still waiting halfway to its deadline, while at least three minutes are left (see Reminders). A destination that lists `reminder` alone is an escalation destination: it gets the reminder and never the announcement. |

The list is not empty, names each message once, and lists `closed` only beside `pending` or `reminder`, because an outcome follows a message the destination received. A `security-events` destination takes no list. A file that breaks any of these is refused when the service starts, and a reload refuses a change to the list: restart to change it. A destination receives at most one message of each kind for an approval.

```json
{"destination_id": "soc", "tenant_id": "0f9d…", "kind": "webhook", "url": "https://soc.example.com/execbound", "secret": "…", "messages": ["pending", "closed"]}
```

## Delivery

- Nothing is sent from the request itself. A scheduled job delivers the queue, so a notification arrives shortly after the approval is created, not in the same instant. The jobs service delivers every fifteen seconds; a deployment that runs the drain from its own scheduler sets its own interval. The job drains every workspace a destination names, however it was created, and holds no credential of the workspace's.
- A failed attempt is retried with exponential backoff and marked failed after five attempts, with a code: `RECEIVER_UNAVAILABLE`, `RECEIVER_REFUSED`, `RECEIVER_RATE_LIMITED`, `MAIL_REFUSED`, `MAIL_AUTH_FAILED`, `TLS_UNVERIFIED` or `TLS_UNAVAILABLE`. No retry is scheduled for later than fifteen seconds before the approval's deadline: when the next attempt would fall after that, the notification is marked failed at once with the code of the attempt that failed, so a broken receiver still shows as a failure.
- A notification whose approval is no longer pending is not sent (`APPROVAL_CLOSED`). Nor is one whose approval is still pending but lapses within fifteen seconds (`LAPSED_BEFORE_DELIVERY`), because it could not arrive with time to decide. Neither uses an attempt, and neither changes the approval.
- A queued notification whose message its destination no longer lists, because the service was restarted with a changed `messages` list, is not sent (`MESSAGE_OFF`).
- A queued notification that no drain will reach again, because its destination was removed or because its approval closed after its workspace's last destination went, is settled by the scheduled recovery job with `DESTINATION_UNKNOWN` or `APPROVAL_CLOSED`, and nothing is sent. One whose destination is gone is settled once it is a day old.
- The console's approval page shows each pending approval's delivery state.

What the approval page shows about delivery: for every reader, under the quorum, when the announcement arrived against the deadline ("Notification delivered 14:08:31 EDT, 2 min before the deadline.", or after it), how many of several destinations it reached, and, for one that was never sent, why: "Not sent: the approval lapsed before delivery." (`LAPSED_BEFORE_DELIVERY`, or `APPROVAL_CLOSED` when the scheduled sweep ended the approval first), "Not sent: decided before delivery." (the approval was decided first, or approved and then never used), or "Not sent: the request was no longer valid." (the request stopped being valid before anyone decided it). In the Lapsed view an administrator sees "Message late" on each approval whose message lapsed unsent or arrived within 30 seconds of the deadline, and a note that a longer approval deadline gives people time to answer.
- Email subjects read `[ExecBound · <workspace> · EB-20] Decide by 13:36:24 UTC: <action> on <resource class>` (see What a message says). Each workspace sends at most 500 messages in any 24 hours by default, of every kind. An announcement over the cap waits an hour and is tried again when its approval would still be open then; otherwise it is marked failed with `RATE_LIMITED`, since a message an hour late would arrive after the deadline. A reminder or an outcome message is sent only while the day's count is below the cap less a tenth of it (at least one message), so the last of the cap is kept for new requests; over that it is marked failed with `RATE_LIMITED` at once and never deferred.
- Each Slack or Teams destination gets at most one message a second, and a `Retry-After` from the channel is honoured.

A notification never grants, extends or replaces an approval, and a failed delivery never changes an approval or an execution.

## What a message says

Email, Slack and Teams messages are fixed text. The workspace and space names and every label are reduced to letters, digits, spaces and `._:/()-` before they are shown. The agent that asked is named by its handle in the workspace, such as "Agent 3", never by a label an administrator gave it, and nothing the agent sent appears in a message.

The deadline is given to the second, in UTC: as a time when it falls on the day the message was sent, and with the date when it does not. How long is left is worded as of sending, such as "About 4 minutes", because a message read later must not claim a fresh count.

An email:

```text
Subject: [ExecBound · Synthetic SOC · EB-20] Decide by 13:36:24 UTC: Isolate endpoint on workstation

Decide by 13:36:24 UTC in Synthetic SOC.
About 4 minutes to decide when this was sent.

Request: EB-20
Action: Isolate endpoint
Resource class: workstation
Environment: production
Space: Default
Requested by: Agent 3
Decide by: 2026-10-08 13:36:24 UTC

Open the approval: <link>

If the console does not load, use the basic page: <link>/classic

This message decides nothing. Approve or refuse on the page, signed in as yourself. If the deadline passes, nothing runs.
You receive this because this address is a notification destination for Synthetic SOC.
Sent automatically; replies are not read.
```

`Approvals recorded: 1 of 2` follows `Requested by` when the approval needs more than one approver.

A Slack or Teams message has the header `EB-20 · Isolate endpoint needs a decision`, and Slack's notification text reads `EB-20 · Isolate endpoint needs a decision by 13:36:24 UTC in Synthetic SOC`. Its facts lead with the deadline: Decide by (with the date), Time to decide ("About 4 minutes when sent"), Workspace, Space, Action, Resource class, Environment and Requested by, then Approvals recorded when there is a quorum. A channel is not an address, so a card carries the Workspace and Space facts instead of the email's last sentence.

The webhook body below is unchanged by any of this.

## Reminders

A destination that lists `reminder` is told once more about a request nobody has decided by halfway to its deadline. The drain queues the reminder at the start of a run once half the approval's time to decide has passed, and only while at least three minutes are left, so it can still arrive with time to act: with a ten-minute deadline it goes out at the first run after five minutes. A window shorter than six minutes never gets one, because less than three minutes are left at its halfway point, and that includes the two-minute minimum deadline and an approval capped by a five-minute context. A longer window gets one only if a delivery run falls between its halfway point and three minutes before its deadline.

A reminder is routed as the announcement is, by the request's target, action and space and by the destination's `approvers` list. Each destination gets at most one reminder for an approval. It is sent under the announcement's rules: not once the approval is decided (`APPROVAL_CLOSED`) or within fifteen seconds of its deadline (`LAPSED_BEFORE_DELIVERY`), and no retry later than that. A reminder never extends the deadline or changes the approval in any way.

A destination that lists only `reminder` is an escalation destination: it gets the reminder for each matching approval still waiting, and never the announcement. Use one for an address or channel that should hear only of requests nobody has picked up in time.

A reminder is the announcement again, saying it is still waiting. The email's subject and first line change, and the rest of the message is the announcement's:

```text
Subject: [ExecBound · Synthetic SOC · EB-20] Still waiting, decide by 13:36:24 UTC: Isolate endpoint on workstation

Still waiting for a decision. Decide by 13:36:24 UTC in Synthetic SOC.
About 4 minutes to decide when this was sent.

Request: EB-20
…
```

A Slack or Teams reminder has the header `EB-20 · Isolate endpoint still needs a decision`, and Slack's notification text reads `EB-20 · Isolate endpoint still needs a decision by 13:36:24 UTC in Synthetic SOC`; the facts and buttons are the announcement's. The webhook body is the announcement's byte for byte except for `"kind":"approval.reminder"`, with the same `expires_at`, because a reminder moves nothing. `approval.reminder` is an additive kind: only a destination whose `messages` list `reminder` receives it, so a receiver that never reads `kind` never sees one.

## Outcomes

A destination that lists `closed` gets one more message for each approval it was told of: how it ended, and when. The drain queues it at the start of a run once the approval is decided, withdrawn, or 30 seconds past its deadline with nobody deciding, and only when the announcement was delivered within the last day and the approval ended within the last hour; an outcome that would arrive later than that is not sent. The outcome and its time are fixed when it is queued, so a retry says the same thing.

| Outcome | Email subject | Card header | First line |
| --- | --- | --- | --- |
| Approved | `[ExecBound · <workspace> · EB-20] Approved: <action> on <resource class>` | `EB-20 · <action>: approved` | `EB-20 was approved at 13:35:10 UTC.` |
| Refused | `… Refused: …` | `…: refused` | `EB-20 was refused at 13:35:10 UTC.` |
| Lapsed | `… Lapsed without a decision: …` | `…: lapsed without a decision` | `EB-20 lapsed without a decision at 13:36:24 UTC.` |
| Withdrawn | `… Closed without a decision: …` | `…: closed without a decision` | `EB-20 closed without a decision by 13:36:40 UTC.` |

Withdrawn means the approval ended before its deadline without a decision, for example because the policy or the request's facts changed. Every outcome message then says "This message decides nothing and does not say whether the action ran. The approval page has the record.", links the approval, and names no person and no target. An email outcome is a reply to the announcement (`In-Reply-To` and `References`), so a mailbox shows it beneath the request. A Slack or Teams outcome is a new message with Workspace, Outcome and At facts and one button to the approval: an incoming webhook cannot edit the message it posted.

**An outcome is not permission.** `approved` reports a person's decision on the approval page; it does not say the action ran, and a receiving system must not act on it as if ExecBound had authorised anything. Only the gateway decides whether an action runs.

The webhook body of an outcome is its own compact JSON, signed like every other body:

```json
{"action":"endpoint.isolate","approval_id":"8c6a…","approval_url":"https://app.execbound.ai/approvals","closed_at":"2026-10-08T13:35:10+00:00","execution_id":"a37d…","kind":"approval.closed","outcome":"approved","tenant_id":"0f9d…","version":1}
```

`outcome` is `approved`, `refused`, `lapsed` or `withdrawn`. `approval.closed` is an additive kind: only a destination whose `messages` list `closed` receives it, so a receiver that never reads `kind` never sees one.

## The webhook body

```http
POST /your/endpoint HTTP/1.1
Content-Type: application/json
X-ExecBound-Delivery: 5f0c2b8e-3a51-4c7e-9d7a-2b6f1c0e8a41
X-ExecBound-Signature: <hex HMAC-SHA256>
```

```json
{"action":"endpoint.isolate","approval_id":"8c6a…","approval_url":"https://app.execbound.ai/approvals","assigned_approvers":2,"canonical_target_id":"4b1e…","environment":"production","execution_id":"a37d…","expires_at":"2026-09-25T14:02:00+00:00","kind":"approval.pending","resource_class":"endpoint","tenant_id":"0f9d…","version":1}
```

| Field | Meaning |
| --- | --- |
| `version` | `1`. |
| `kind` | `approval.pending`, or `approval.reminder` for a reminder (see Reminders). An outcome has its own body (see Outcomes). |
| `tenant_id` | The workspace. |
| `approval_id`, `execution_id` | The approval and the execution it holds. |
| `action` | The action waiting, such as `endpoint.isolate`. |
| `resource_class` | The kind of target. |
| `environment` | The target's environment. |
| `canonical_target_id` | The target. |
| `expires_at` | When the approval lapses if nobody decides. |
| `assigned_approvers` | How many people may decide it. |
| `approval_url` | The console's approvals page, where they decide. |

The body is compact JSON with its keys sorted. It names no person, no resource name and no argument value.

## Weekly summary

A person may turn on a plain-text summary under My account, where the deployment's `mail` block sets `weekly_summary: true` ([Operations](OPERATIONS.md#send-notifications-by-email)). It is off until they turn it on, and there is no workspace-wide switch. Each Monday it goes to the address the workspace holds for them, the one My account shows, and says, for the seven days to Monday 00:00 UTC and in their own scope: requests made against the week before, executed, refused by policy or a failed check, by an impact limit and because another request held the target, held for a person and what became of them, the median time to decide, what is still unsettled or has an unknown effect, monitoring health for an administrator as reported by sources, and observe mode's would-have counts under their own heading. It says that these are counts of what ExecBound recorded and that a refusal is not proof that harm was prevented.

Besides the link that stops it, it carries one link, the console's address, and no agent, provider, target or person, no request or approval identifier and no control. A week with nothing in it sends nothing. Each summary carries `List-Unsubscribe` and `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058), so a mail client's unsubscribe button stops it in one click without signing in, and the link at its foot does the same; a link from an older summary cannot stop a subscription turned on again since. The deployment sends at most `weekly_summary_daily_cap` summaries a day and each workspace at most its `daily_limit`; a summary over either waits for the next hourly run.

## Verify the signature

The signature is the lowercase hex HMAC-SHA256 of the delivery id, a newline, and the exact body bytes, keyed with the destination's `secret`. Check it against the raw body before parsing it:

```python
import hashlib
import hmac


def verified(secret: str, delivery_id: str, body: bytes, signature: str) -> bool:
    expected = hmac.new(
        secret.encode("ascii"), delivery_id.encode("ascii") + b"\n" + body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

- Answer 200 or 204 within five seconds. Any other answer, a redirect or a timeout counts as a failed attempt.
- The same delivery can arrive more than once after an attempt whose answer was lost. Keep the `X-ExecBound-Delivery` ids you have handled and ignore a repeat; that is also what stops a recorded delivery being replayed, since the signature carries no timestamp.
- Monitoring alerts and the security event export use the same two headers and the same signature.
