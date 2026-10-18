// SPDX-License-Identifier: AGPL-3.0-only
// Runs only on the dedicated MFA page. No analytics, remote scripts or storage.
const promptButton = document.getElementById("passkey-prompt");
const ceremonyForm = document.getElementById("passkey-finish");
const problem = document.getElementById("passkey-problem");
function decode(value) {
  const raw = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(raw, (letter) => letter.charCodeAt(0));
}
function encode(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
if (promptButton && ceremonyForm) promptButton.addEventListener("click", async () => {
  promptButton.disabled = true;
  problem.textContent = "";
  try {
    if (!window.PublicKeyCredential) throw new Error("unsupported");
    const options = JSON.parse(document.getElementById("passkey-options").value);
    const registration = ceremonyForm.dataset.ceremony === "register";
    options.challenge = decode(options.challenge);
    if (options.user) options.user.id = decode(options.user.id);
    for (const list of [options.allowCredentials, options.excludeCredentials]) {
      for (const item of list || []) item.id = decode(item.id);
    }
    const credential = registration
      ? await navigator.credentials.create({ publicKey: options })
      : await navigator.credentials.get({ publicKey: options });
    if (!credential) throw new Error("cancelled");
    const response = { clientDataJSON: encode(credential.response.clientDataJSON) };
    if (registration) response.attestationObject = encode(credential.response.attestationObject);
    else {
      response.authenticatorData = encode(credential.response.authenticatorData);
      response.signature = encode(credential.response.signature);
      if (credential.response.userHandle) response.userHandle = encode(credential.response.userHandle);
    }
    ceremonyForm.elements.credential.value = JSON.stringify({
      id: credential.id, rawId: encode(credential.rawId), type: credential.type, response,
    });
    ceremonyForm.requestSubmit();
  } catch {
    problem.textContent = "The passkey prompt was cancelled or unavailable. Try again, or return to account security to use an authenticator or recovery code.";
    promptButton.disabled = false;
  }
});
