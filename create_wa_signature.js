import antelopeWebAuthnSignature from "./_utils/webauthn_signature.js";
export default async function createWebAuthnSignature(device_key, hash) {
    const challenge = typeof hash == "string"
        ? (() => {
            const matches = hash.match(/[a-fA-F0-9]{2}/gmu);
            if (matches)
                return Uint8Array.from(matches.map((x) => Number(`0x${x}`)));
            // Handle the case where match returns null (no valid hex found)
            else
                throw new Error("Invalid hash string format");
        })()
        : hash;
    const allowCredentials = [
        {
            id: Uint8Array.from(window
                .atob(device_key.credential_id.replace(/-/gmu, "+").replace(/_/gmu, "/"))
                .split("")
                .map((i) => i.charCodeAt(0))),
            type: "public-key",
            alg: -7,
        },
    ];
    const assertation = (await window.navigator.credentials.get({
        publicKey: {
            allowCredentials,
            challenge,
            timeout: 6e4,
            userVerification: "required",
        },
    }));
    const response = assertation.response;
    const antelope_signature = antelopeWebAuthnSignature(response, device_key.public_key);
    return antelope_signature;
}
