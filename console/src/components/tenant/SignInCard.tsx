// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  readSignInOptions,
  readSignInQueryKey,
  registerProviderMutation,
  setProviderStateMutation,
} from "../../api/@tanstack/react-query.gen";
import type { SignInView } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { copyFor, refusal } from "../../lib/refusal";
import { can, useSession } from "../../lib/session";
import { toast } from "../../lib/toast";
import { when } from "../../lib/when";
import { Badge, type Tone } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Field } from "../ui/Field";
import { FormDialog } from "../ui/FormDialog";

/**
 * The tenant's own identity provider (#177, #241): register one, prove it works by signing in
 * through it, enable it, disable it.
 *
 * Two things on this card are meant to be copied rather than read. The redirect URI is what a
 * customer pastes at Entra ID or Okta, and it is the same string for every tenant, which is why
 * it can be shown before anything is registered. The sign-in address is what an administrator
 * hands to the people who will use it; knowing it buys nobody anything, because it sends a
 * browser to the customer's own login page and a subject with no link is refused on return.
 *
 * The provider signs people in to the whole workspace, so only a workspace administrator
 * configures it (0073): an administrator narrowed to spaces reads the card, because their
 * people's invitations stand on the provider it describes, and is offered no registration,
 * test sign-in or state change. Linking their own account through an enabled provider is
 * theirs, as it is anybody's.
 */
const TONES: Record<SignInView["provider"] extends null ? never : string, Tone> = {
  draft: "hold",
  verified: "obs",
  enabled: "allow",
  disabled: "stale",
};

const STATE_WORDS: Record<string, string> = {
  draft: "Not verified",
  verified: "Verified, not yet enabled",
  enabled: "Enabled",
  disabled: "Disabled",
};

/** The lines the register form shows for the fields the API can name. */
const SIGN_IN_FIELDS: Record<string, string> = {
  issuer:
    "The issuer must be an https address this server can fetch a discovery document from, and an Entra issuer must name one directory rather than common, organizations or consumers.",
  client_secret: "The client secret could not be stored. Check the deployment's key ring.",
  name: "A name of 1 to 80 characters is required.",
  client_id: "A client id of 1 to 256 characters is required.",
  subject_claim: "Choose sub or oid.",
};

export function SignInCard() {
  // Never `throwOnError`: the mode, the deadline and the stop are what this page is for, and
  // a directory that cannot be read must not take them down with it.
  const query = useQuery({ ...readSignInOptions(), throwOnError: false });
  // Workspace-wide `access.manage`, which an administrator narrowed to spaces does not hold.
  const configures = can(useSession(), "access.manage");
  const [registering, setRegistering] = useState(false);
  const [changing, setChanging] = useState<"enabled" | "disabled" | null>(null);
  const view = query.data;
  if (view === undefined) {
    // A first read that failed renders nothing at all rather than a card that says "Loading"
    // for ever: the page's other cards are what this page is for, and the audit waits for every
    // placeholder to be gone. A later read that fails leaves the card it read, and any dialog
    // open on it.
    if (query.isError) return null;
    return (
      <Card title="Sign-in provider">
        <p className="muted" role="status">
          Loading the provider
        </p>
      </Card>
    );
  }
  if (!view.configured) {
    return (
      <Card title="Sign-in provider">
        <p className="muted">
          This deployment was not given a key ring, so there is nowhere to keep a provider&apos;s
          client secret and no provider can be registered. The operator adds one to the private
          configuration.
        </p>
      </Card>
    );
  }
  const provider = view.provider;
  return (
    <Card title="Sign-in provider">
      {provider === null ? (
        <>
          <p className="muted">
            Users in this tenant sign in with an address and a password, or with a configured
            provider. Register your own OpenID Connect provider to sign in with your directory
            instead, and to end access here when an account is disabled there.
          </p>
          {configures ? (
            <>
              <Redirect view={view} />
              <div className="row">
                <Button
                  variant="primary"
                  onClick={() => {
                    setRegistering(true);
                  }}
                >
                  Register a provider
                </Button>
              </div>
            </>
          ) : (
            <WorkspaceOnly />
          )}
        </>
      ) : (
        <>
          <p>
            <Badge tone={TONES[provider.state] ?? "stale"}>{STATE_WORDS[provider.state]}</Badge>{" "}
            <span>{provider.name}</span>
          </p>
          <dl className="facts">
            <dt>Issuer</dt>
            <dd className="mono">{provider.issuer}</dd>
            <dt>Client id</dt>
            <dd className="mono">{provider.client_id}</dd>
            <dt>Subject claim</dt>
            <dd className="mono">{provider.subject_claim}</dd>
            <dt>Users linked</dt>
            <dd>{provider.linked}</dd>
            <dt>Last sign-in</dt>
            <dd>{provider.last_sign_in_at !== null ? when(provider.last_sign_in_at) : "None yet"}</dd>
          </dl>
          <Redirect view={view} />
          {view.sign_in_url !== null ? (
            <Copyable
              label="Your tenant's sign-in address"
              value={view.sign_in_url}
              hint="Hand this to the users who will use it. A browser that has signed in through your directory once is offered the button on the sign-in page afterwards."
            />
          ) : null}
          {!configures ? <WorkspaceOnly /> : null}
          {configures && provider.state === "draft" ? (
            <p className="note">
              Nobody has signed in through this provider yet. Paste the redirect URI above at your
              provider, then test it: a sign-in that works links your own account and marks this
              verified. Enabling before that is refused, because a provider nobody has been through
              is how a tenant locks itself out.
            </p>
          ) : null}
          <div className="row">
            {configures && (provider.state === "draft" || !provider.self_linked) ? (
              <Button
                variant="primary"
                onClick={() => {
                  // A navigation rather than a fetch: the flow has to leave for the provider and
                  // come back, and the session cookie is what says who is linking.
                  window.location.assign(`/login/directory/${provider.provider_id}/link`);
                }}
              >
                {provider.state === "draft" ? "Test sign-in" : "Link my account"}
              </Button>
            ) : null}
            {!configures && provider.state === "enabled" && !provider.self_linked ? (
              <Button
                variant="primary"
                onClick={() => {
                  window.location.assign(`/login/directory/${provider.provider_id}/link`);
                }}
              >
                Link my account
              </Button>
            ) : null}
            {configures && (provider.state === "verified" || provider.state === "disabled") ? (
              <Button
                onClick={() => {
                  setChanging("enabled");
                }}
              >
                Enable
              </Button>
            ) : null}
            {configures && provider.state === "enabled" ? (
              <Button
                variant="danger"
                onClick={() => {
                  setChanging("disabled");
                }}
              >
                Disable
              </Button>
            ) : null}
          </div>
        </>
      )}
      <RegisterDialog
        open={registering}
        onClose={() => {
          setRegistering(false);
        }}
      />
      <StateDialog
        state={changing}
        providerId={provider?.provider_id ?? null}
        linked={provider?.linked ?? 0}
        onClose={() => {
          setChanging(null);
        }}
      />
    </Card>
  );
}

/** What a narrowed administrator is told in place of the controls they do not hold. */
function WorkspaceOnly() {
  return (
    <p className="note">
      Only a workspace administrator registers, tests, enables or disables the sign-in provider,
      because it signs people in to the whole workspace.
    </p>
  );
}

function Redirect({ view }: { view: SignInView }) {
  if (view.redirect_uri === null) return null;
  return (
    <Copyable
      label="Redirect URI to register at your provider"
      value={view.redirect_uri}
      hint="The same address for every tenant of this deployment. Your provider must be given exactly this and nothing else."
    />
  );
}

function Copyable({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <input
        className="mono"
        type="text"
        readOnly
        value={value}
        autoComplete="off"
        spellCheck={false}
        onFocus={(event) => {
          event.currentTarget.select();
        }}
      />
      <small>{hint}</small>
    </label>
  );
}

function useSignInChange<TVariables>(
  options: Parameters<typeof useServerMutation<SignInView, TVariables>>[0],
  onDone: () => void,
) {
  const queryClient = useQueryClient();
  return useServerMutation<SignInView, TVariables>({
    ...options,
    onSuccess: (view) => {
      queryClient.setQueryData(readSignInQueryKey(), view);
      onDone();
    },
  });
}

function RegisterDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [name, setName] = useState("");
  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [claim, setClaim] = useState<"sub" | "oid">("oid");
  const register = useSignInChange(registerProviderMutation(), () => {
    toast("Registered. Test the sign-in to verify it.");
    setClientSecret("");
    onClose();
  });
  const faults = register.isError ? refusal(register.error).fields : [];
  return (
    <FormDialog
      open={open}
      onClose={onClose}
      title="Register an identity provider"
      description="The discovery document is fetched and checked before anything is saved, so a provider that could not work is refused here rather than at somebody's first sign-in."
      confirm="Register"
      pending={register.isPending}
      error={register.isError && faults.length === 0 ? copyFor(register.error, SIGN_IN_FIELDS) : undefined}
      onSubmit={() => {
        register.mutate({
          body: {
            name: name.trim(),
            issuer: issuer.trim(),
            client_id: clientId.trim(),
            client_secret: clientSecret,
            subject_claim: claim,
          },
        });
      }}
    >
      <Field id="idp-name" label="Name" error={faults.includes("name") ? SIGN_IN_FIELDS.name : undefined}>
        <input
          id="idp-name"
          type="text"
          required
          maxLength={80}
          value={name}
          placeholder="Contoso"
          onChange={(event) => {
            setName(event.target.value);
          }}
        />
      </Field>
      <Field
        id="idp-issuer"
        label="Issuer"
        hint="Entra ID: https://login.microsoftonline.com/<your directory id>/v2.0. Okta: https://<your org>.okta.com/oauth2/<server>."
        error={faults.includes("issuer") ? SIGN_IN_FIELDS.issuer : undefined}
      >
        <input
          id="idp-issuer"
          className="mono"
          type="url"
          required
          maxLength={512}
          value={issuer}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => {
            setIssuer(event.target.value);
          }}
        />
      </Field>
      <Field
        id="idp-client"
        label="Client id"
        error={faults.includes("client_id") ? SIGN_IN_FIELDS.client_id : undefined}
      >
        <input
          id="idp-client"
          className="mono"
          type="text"
          required
          maxLength={256}
          value={clientId}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => {
            setClientId(event.target.value);
          }}
        />
      </Field>
      <Field
        id="idp-secret"
        label="Client secret"
        hint="Kept encrypted and never shown again. To change it, register the provider afresh."
        error={faults.includes("client_secret") ? SIGN_IN_FIELDS.client_secret : undefined}
      >
        <input
          id="idp-secret"
          type="password"
          required
          maxLength={2048}
          value={clientSecret}
          autoComplete="off"
          onChange={(event) => {
            setClientSecret(event.target.value);
          }}
        />
      </Field>
      <Field
        id="idp-claim"
        label="Subject claim"
        hint="oid for Entra ID, whose sub differs per application; sub elsewhere. An address is never an identifier."
      >
        <select
          id="idp-claim"
          value={claim}
          onChange={(event) => {
            setClaim(event.target.value === "sub" ? "sub" : "oid");
          }}
        >
          <option value="oid">oid</option>
          <option value="sub">sub</option>
        </select>
      </Field>
    </FormDialog>
  );
}

function StateDialog({
  state,
  providerId,
  linked,
  onClose,
}: {
  state: "enabled" | "disabled" | null;
  providerId: string | null;
  linked: number;
  onClose: () => void;
}) {
  const change = useSignInChange(setProviderStateMutation(), () => {
    toast(state === "enabled" ? "The provider is enabled." : "The provider is disabled.");
    onClose();
  });
  if (providerId === null) return null;
  return (
    <FormDialog
      open={state !== null}
      onClose={onClose}
      title={state === "enabled" ? "Enable this provider?" : "Disable this provider?"}
      description={
        state === "enabled"
          ? "Everyone you have linked or invited can sign in with it. Addresses, passwords and credentials keep working beside it."
          : `Every session standing on this provider ends at once${linked > 0 ? `, for ${String(linked)} linked ${linked === 1 ? "user" : "users"}` : ""}. Links and invitations are kept, so enabling it again restores them.`
      }
      confirm={state === "enabled" ? "Enable it" : "Disable it"}
      pending={change.isPending}
      error={change.isError ? copyFor(change.error, SIGN_IN_FIELDS) : undefined}
      onSubmit={() => {
        if (state !== null) {
          change.mutate({ path: { provider_id: providerId }, body: { state } });
        }
      }}
    />
  );
}
