import assertBrowserCompatibility from "./browser-compatability.js";
import { validateChallenge } from "./validate-challenge.js";
/**
 * Wraps `navigator.credentials.get` to request a WebAuthn assertion from the
 * user's authenticator.
 *
 * This is the low-level building block used by {@link antelopeSign}. Use
 * `antelopeSign` for the full end-to-end signing flow; call this directly only
 * when you need fine-grained control over the `CredentialRequestOptions`.
 *
 * @param options - Standard `CredentialRequestOptions` passed directly to
 *   `navigator.credentials.get`. The `publicKey.challenge` field must be set.
 * @returns The `PublicKeyCredential` returned by the authenticator, containing
 *   an `AuthenticatorAssertionResponse` with `authenticatorData`,
 *   `clientDataJSON`, and `signature`.
 * @throws {Error} If the browser does not support the WebAuthn API.
 * @throws {Error} If `publicKey.challenge` is absent or invalid.
 * @throws {DOMException} If the user cancels the authentication gesture or the
 *   authenticator returns an error.
 */
export default async function authenticatorAssertion(options) {
    assertBrowserCompatibility();
    validateChallenge(options.publicKey?.challenge);
    const assertation = (await window.navigator.credentials.get({
        ...options,
        publicKey: options.publicKey,
    }));
    return assertation;
}
