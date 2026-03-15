import assertBrowserCompatibility from "./browser-compatability.js";

export type CreateWebAuthnKeyResult = {
  id: string;
  rawId: ArrayBuffer;
  type: PublicKeyCredential["type"];
  response: AuthenticatorAttestationResponse;
  authenticatorAttachment: PublicKeyCredential["authenticatorAttachment"];
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
};

/**
 * Creates a new webauthn credential, its attestation response, and related metadata by calling `navigator.credentials.create` with the provided options.
 */
export default async function authenticatorAttestation(
  options: CredentialCreationOptions
): Promise<CreateWebAuthnKeyResult> {
  assertBrowserCompatibility();

  const cred = (await navigator.credentials.create(
    options
  )) as PublicKeyCredential | null;

  if (!cred) {
    throw new Error("Failed to create WebAuthn credential.");
  }

  const response = cred.response as AuthenticatorAttestationResponse;

  return {
    id: cred.id,
    rawId: cred.rawId,
    type: cred.type,
    response,
    authenticatorAttachment: cred.authenticatorAttachment ?? null,
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}
