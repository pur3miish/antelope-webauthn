import assertBrowserCompatibility from "./_utils/browser-compatability.js";
import antelopeWebAuthnPublicKey from "./_utils/webauthn-public-key.js";

export default async function createWebAuthnKey(
  options: CredentialCreationOptions
): Promise<PublicKeyCredential & { antelope_public_key: string }> {
  assertBrowserCompatibility();

  const cred = (await navigator.credentials.create(
    options
  )) as PublicKeyCredential;

  const response = cred.response as AuthenticatorAttestationResponse;
  const antelope_public_key = await antelopeWebAuthnPublicKey(response);

  return {
    ...cred,
    antelope_public_key,
  };
}
