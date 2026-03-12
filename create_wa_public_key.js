import assertBrowserCompatibility from "./_utils/browser-compatability";
import antelopeWebAuthnPublicKey from "./_utils/webauthn-public-key.js";
export default async function createWebAuthnKey(options) {
    assertBrowserCompatibility();
    const cred = (await navigator.credentials.create(options));
    const response = cred.response;
    const antelope_public_key = await antelopeWebAuthnPublicKey(response);
    return {
        ...cred,
        antelope_public_key,
    };
}
