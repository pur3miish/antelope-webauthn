import assertBrowserCompatibility from "./browser-compatability.js";
import { validateChallenge } from "./validate-challenge.js";
/**
 * Creates a new webauthn signature response by calling `navigator.credentials.get` with the provided options.
 * This function is used internally by the `antelopeSign` function to generate signatures using webauthn credentials.
 * It takes a `CredentialRequestOptions` object as input and returns a `PublicKeyCredential` containing the assertion response from the authenticator.
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
