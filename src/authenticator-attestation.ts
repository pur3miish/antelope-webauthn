import assertBrowserCompatibility from "./_utils/browser-compatability.js";
import antelopeWebAuthnPublicKey from "./create-antelope-publickey.js";

export type CreateWebAuthnKeyResult = {
  id: string;
  rawId: ArrayBuffer;
  type: PublicKeyCredential["type"];
  response: AuthenticatorAttestationResponse;
  authenticatorAttachment: PublicKeyCredential["authenticatorAttachment"];
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  antelope_public_key: string;
};

/**
 * creates a new webauthn credential and returns an Antelope compatible public key along with the attestation response and other relevant information.
 * @param options
 * @returns
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
