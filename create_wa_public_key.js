import assertBrowserCompatibility from "./_utils/browser-compatability";
import antelopeWebAuthnPublicKey from "./_utils/webauthn-public-key.js";
export default async function createWebAuthnKey({ id = crypto.getRandomValues(new Uint8Array(16)), email, displayName, relayingParty, challenge, }) {
    assertBrowserCompatibility();
    const cred = (await navigator.credentials.create({
        publicKey: {
            rp: { id: relayingParty, name: relayingParty },
            user: { id, name: email, displayName },
            pubKeyCredParams: [
                { type: "public-key", alg: -7 },
                { type: "public-key", alg: -257 },
            ],
            attestation: "direct",
            timeout: 6e4,
            challenge: challenge.buffer,
        },
    }));
    const response = cred.response;
    const antelope_public_key = await antelopeWebAuthnPublicKey(response);
    return { public_key: antelope_public_key, credential_id: cred.id, id };
}
