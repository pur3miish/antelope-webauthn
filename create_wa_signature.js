import assertBrowserCompatibility from "./_utils/browser-compatability.js";
import { credentialIdToUint8Array } from "./_utils/credential-id-to-uint8array.js";
import { hexToUint8Array } from "./_utils/hex-to-uint8array.js";
import antelopeWebAuthnSignature from "./_utils/webauthn_signature.js";
import createAuthenticatorAssertionResponse from "./create-authenticator-assertion-response.js";
export default async function createAntelopeSignature(device_keys, hash) {
    assertBrowserCompatibility();
    const allowCredentials = device_keys.map((key) => ({
        id: credentialIdToUint8Array(key.credential_id),
        type: "public-key",
        alg: -7,
    }));
    const assertation = (await createAuthenticatorAssertionResponse({
        publicKey: {
            allowCredentials,
            challenge: typeof hash == "string" ? hexToUint8Array(hash) : hash,
            timeout: 6e4,
            userVerification: "required",
        },
    }));
    const response = assertation.response;
    const device_key = device_keys.find((x) => x.credential_id == assertation.id);
    if (!device_key?.public_key)
        throw new Error("We were unable to produce a valid signature with the device keys you provided.");
    const antelope_signature = antelopeWebAuthnSignature(response, device_key.public_key);
    return antelope_signature;
}
