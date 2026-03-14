import assertBrowserCompatibility from "./_utils/browser-compatability.js";
import antelopeWebAuthnPublicKey from "./_utils/webauthn-public-key.js";
export default async function createWebAuthnKey(options) {
    assertBrowserCompatibility();
    const cred = (await navigator.credentials.create(options));
    if (!cred) {
        throw new Error("Failed to create WebAuthn credential.");
    }
    const response = cred.response;
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
