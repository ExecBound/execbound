# Security policy

ExecBound decides whether an AI agent's action may run, and holds the credentials that carry the action out. A vulnerability here can matter more than it would in most software, so thank you for reporting one privately.

## Reporting a vulnerability

Email **justin.pitt@execbound.ai** with:

- the affected component, and the version or commit;
- the steps to reproduce it;
- the impact, as you understand it;
- a safe proof of concept.

Do not send credentials, secrets or anyone else's data. If your evidence is sensitive, ask for a secure way to send it before you send it.

Where this repository offers GitHub's private vulnerability reporting ("Report a vulnerability" on its Security tab), a report made there is accepted too.

Please do not report a vulnerability in a public issue, pull request or discussion.

## What happens next

ExecBound is a small team, and every report is read by a person.

- **We acknowledge your report within five business days.**
- **Disclosure is coordinated, within 90 days.** We agree a disclosure date with you, no later than 90 days after your report. If a fix needs longer, we tell you why before the 90 days end and agree a new date with you.

No bug bounty is offered at present.

## Testing safely

- Test against your own deployment, or against your own workspace on the hosted service holding synthetic data only.
- Do not attempt denial of service, social engineering, persistence or destruction, and do not access, or try to access, another tenant or workspace.
- If you come across someone else's data, stop, and report it privately with the least evidence that shows the problem.

This policy does not authorise access to any third party's systems.

## Supported versions

Security fixes are made in the latest release only, so upgrade to it to receive them.

## Scope

In scope: the code in this repository, and the hosted service at `app.execbound.ai` within the rules above.

The findings that matter most are anything that lets an agent:

- obtain a credential, in any form;
- reach a route or an operation beyond proposing its own actions, reading their status and reading back its own identity;
- approve its own request, or act without an approval that policy requires;
- exceed a shared impact limit, including by splitting work across agents or protocols;
- read or change another tenant's data, or alter the audit record.

Out of scope:

- vulnerabilities in the vendor systems ExecBound connects to, which belong with that vendor;
- weaknesses that need an attacker to already hold the deployment's private configuration or its database owner access. The [threat model](docs/THREAT_MODEL.md) and [Where credentials live](docs/CREDENTIALS.md) state these as outside what ExecBound protects against. A way to *obtain* that access is in scope, and we want to hear about it.

## How ExecBound handles credentials

An agent holds one credential, its own ExecBound token, and it opens only the agent routes: proposing an action, reading the status of its own requests, and reading back its own identity. The vendor credential that performs an action stays with the connector and never reaches the agent in any form. Every credential ExecBound keeps, the form it is kept in, where, who can read it, and where that protection stops, is set out in [Where credentials live](docs/CREDENTIALS.md).
