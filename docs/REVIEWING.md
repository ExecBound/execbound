# Reviewing actions with an existing account

Reviewers use their normal ExecBound account. A notification links to the request; it
does not contain a sign-in credential or authority to approve. A signed-out person signs
in with their existing password, configured provider or organisation directory, then
returns to that request. The classic, server-rendered approval link supports the same flow.

An administrator manages users and their roles under **Users** or **Groups & roles**.
Under **Approval rules**, a group rule selects the reviewer group, Space, actions and
resources. Individual exceptions remain under **Advanced: individual review assignments**.
A managed user needs the Approver role as well as a matching rule or assignment. Granting
a review scope does not create an account or change sign-in. Role changes may require a fresh
sign-in. A new member still needs ordinary account invitation and sign-in setup.

Authentication alone grants no review permission. Administrators without an assignment see
an empty approval queue, although their Activity access still lets them inspect execution
records. Agent credentials cannot sign in as humans or make approval decisions. Tenant,
space, action and target boundaries apply to every reviewer. Decisions remain attributed
to the same principal that signed in, including in audit exports and offline replay.

Review assignments, identity validity and space access are rechecked when a decision is
made and when an approved execution resumes. Revocation can therefore prevent the effect
even after a person clicked Approve. Quorum still counts distinct people; an administrator
and an ordinary member can satisfy a two-person rule, but one person cannot count twice.
Signing in never extends an approval's deadline or overrides a policy denial.

## Implementation and compatibility

The persisted principal kinds remain `ADMIN` and `HUMAN_APPROVER` for compatibility.
Current role capabilities and exact effective scopes determine review authority. Migration
`0045_review_permissions` updates the existing assignment function to accept both human
kinds. Migration `0047_access_control` adds managed user and group roles;
`0048_approval_rules` adds group routing. The `effective_approval_scopes` view combines
individual assignments and current group membership with the user's live Approver capability.
It is shared by decision/resume checks, queues, search and notifications. Existing legacy
authority is preserved until explicit role replacement. See [Console access](CONSOLE_ACCESS.md).
Apply the migrations before running the matching release.

The approval destination is a navigation hint: a console page of this deployment, such as an
exact UUID approval path, in a signed, HttpOnly, five-minute cookie. The pages it may name are a
closed grammar of core's console routes with UUID parameters and, on a few pages, query values from
closed lists ([Surfaces](SURFACES.md)). It is Lax so a provider callback can read it; the actual
session cookie stays Strict. Invalid or expired hints fall back to the normal landing
page; duplicate cookies are rejected, and a sign-in link naming an address the grammar cannot use
deletes any earlier hint. The hint is deleted after sign-in, grants no access, and cannot name an
external URL. The existing CSRF, OAuth state and PKCE checks remain in force. A console
401 on any page, an approval among them, preserves that page and its filters when asking the
person to sign in again. Signing in from a workspace-scoped approval address opens that workspace
when the account may open it, so the reviewer verifies once, for that workspace, and lands on the
approval; a session already signed in to another workspace still chooses to switch.

The normal `/login` page has no credential field. Initial installation
and automated synthetic fixtures can still explicitly use `/login?setup=1` to exchange a
provisioned setup credential. This is a compatibility entry point into the same session
system, not a reviewer account or a permission grant. Configure ordinary sign-in before
asking someone to review from their phone.

## Request references and qualification

[Request references](REQUEST_REFERENCES.md) link the review, execution, deliveries and
optional external case. Notifications show the same `EB-…` handle used by console search;
full UUIDs remain available in technical details. Case information is caller-reported and
never grants permission.
