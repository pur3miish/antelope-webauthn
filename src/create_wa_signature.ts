import antelopeWebAuthnSignature from "./_utils/webauthn_signature.js";

type device_key = {
  public_key: string;
  credential_id: string;
};

export default async function createWebAuthnSignature(
  device_key: device_key,
  hash: Uint8Array | string
) {
  const challenge =
    typeof hash == "string"
      ? (() => {
          const matches = hash.match(/[a-fA-F0-9]{2}/gmu);
          if (matches)
            return Uint8Array.from(matches.map((x) => Number(`0x${x}`)));
          // Handle the case where match returns null (no valid hex found)
          else throw new Error("Invalid hash string format");
        })()
      : hash;

  const allowCredentials = [
    {
      id: Uint8Array.from(
        window
          .atob(
            device_key.credential_id.replace(/-/gmu, "+").replace(/_/gmu, "/")
          )
          .split("")
          .map((i) => i.charCodeAt(0))
      ),
      type: "public-key" as PublicKeyCredentialType,
      alg: -7 as COSEAlgorithmIdentifier,
    },
  ];

  const assertation = (await window.navigator.credentials.get({
    publicKey: {
      allowCredentials,
      challenge,
      timeout: 6e4,
      userVerification: "required",
    },
  } as CredentialRequestOptions)) as PublicKeyCredential;

  const response = assertation.response as AuthenticatorAssertionResponse;

  const antelope_signature = antelopeWebAuthnSignature(
    response,
    device_key.public_key
  );

  return antelope_signature;
}
