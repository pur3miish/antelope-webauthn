import assertBrowserCompatibility from "./browser-compatability.js";
/**
 * Creates a new webauthn credential, its attestation response, and related metadata by calling `navigator.credentials.create` with the provided options.
 */
export default async function authenticatorAttestation(options) {
    assertBrowserCompatibility();
    const cred = (await navigator.credentials.create(options));
    if (!cred) {
        throw new Error("Failed to create WebAuthn credential.");
    }
    const response = cred.response;
    return {
        id: cred.id,
        rawId: cred.rawId,
        type: cred.type,
        response,
        authenticatorAttachment: cred.authenticatorAttachment ?? null,
        clientExtensionResults: cred.getClientExtensionResults(),
    };
}
