import assertBrowserCompatibility from "./_utils/browser-compatability.js";
import { validateChallenge } from "./_utils/validate-challenge.js";

/**
 *
 * @example
 * ```ts
 * const hexString = "0000000000000000000000000000000000000000000000000000000000000000";
 *
 * const assertation = await createPublicKeyCredential({
 *   publicKey: {
 *     allowCredentials: [
 *       {
 *         id: credentialIfToUint8Array("some-credential-id"),
 *         type: "public-key" as PublicKeyCredentialType,
 *         alg: -7 as COSEAlgorithmIdentifier,
 *       },
 *     ],
 *     challenge: hexToUint8Array(hexString),
 *     timeout: 6e4,
 *     userVerification: "required",
 *   },
 * });
 * ```
 */
export default async function createAuthenticatorAssertionResponse(
  options: CredentialRequestOptions
): Promise<PublicKeyCredential> {
  assertBrowserCompatibility();
  validateChallenge(options.publicKey?.challenge);

  const assertation = (await window.navigator.credentials.get({
    ...options,
    publicKey: options.publicKey,
  } as CredentialRequestOptions)) as PublicKeyCredential;

  return assertation;
}
