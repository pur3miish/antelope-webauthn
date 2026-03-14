import assertBrowserCompatibility from "./_utils/browser-compatability.js";
import antelopeWebAuthnPublicKey from "./_utils/webauthn-public-key.js";

export type CreateWebAuthnKeyResult = {
  id: string;
  rawId: ArrayBuffer;
  type: PublicKeyCredential["type"];
  response: AuthenticatorAttestationResponse;
  authenticatorAttachment: PublicKeyCredential["authenticatorAttachment"];
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  antelope_public_key: string;
};

export default async function createWebAuthnKey(
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
  const antelope_public_key = await antelopeWebAuthnPublicKey(response);

  return {
    id: cred.id,
    rawId: cred.rawId,
    type: cred.type,
    response,
    authenticatorAttachment: cred.authenticatorAttachment ?? null,
    clientExtensionResults: cred.getClientExtensionResults(),
    antelope_public_key,
  };
}
