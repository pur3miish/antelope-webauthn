import base58_to_binary from "base58-js/base58_to_binary.js";

import decodeLEB128 from "./_utils/decodeLEB128";
import sha256 from "./_utils/sha256";

function calculateY(x: bigint, prefix: number) {
  const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
  const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const a = (-3n + p) % p;

  function modPow(base, exponent, modulus) {
    let result = BigInt(1);
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
      }
      base = (base * base) % modulus;
      exponent = exponent >> 1n;
    }
    return result;
  }

  function tonelliShanksAlgorithm(ySquared: bigint, p: bigint) {
    function legendreSymbol(a: bigint, p: bigint) {
      // If a is divisible by p, return 0
      if (a % p === 0n) {
        return 0;
      }
      const symbol = modPow(a, (p - 1n) / 2n, p);
      return symbol === 1n ? 1 : symbol === p - 1n ? -1 : 0;
    }

    if (legendreSymbol(ySquared, p) !== 1)
      throw new Error("No square root exists");

    let q = p - 1n;
    let s = 0n;

    while (q % 2n === 0n) {
      q = q >> 1n;
      s += 1n;
    }

    let z = 2n;
    while (modPow(z, (p - 1n) >> 1n, p) !== p - 1n) {
      z += 1n;
    }

    let c = modPow(z, q, p);
    let r = modPow(ySquared, (q + 1n) >> 1n, p);
    let t = modPow(ySquared, q, p);

    let m = s;
    while (t !== 1n) {
      let temp = t;
      let i = 1n;

      while (temp !== 1n && i < m) {
        temp = (temp * temp) % p;
        i += 1n;
      }

      let b = modPow(c, BigInt(2n ** (m - i - 1n)), p);
      r = (r * b) % p;
      t = (t * b * b) % p;
      c = (b * b) % p;
      m = i;
    }

    return r;
  }

  function calculateYSquared(x: bigint) {
    const xCubed = (((x * x) % p) * x) % p;
    const ax = (a * x) % p;
    const ySquared = (xCubed + ax + b) % p;
    return ySquared;
  }

  const ySquared = calculateYSquared(x);
  const y = tonelliShanksAlgorithm(ySquared, p);

  if (prefix == 2 && y % 2n) return p - y;
  if (prefix == 3 && !(y % 2n)) return p - y;

  return y;
}

function base64UrlEncode(uint8Array: Uint8Array) {
  const base64String =
    typeof btoa !== "undefined"
      ? // @ts-expect-error ts trying to enforce strict type which is unneccessary in this instance.
        btoa(String.fromCharCode.apply(null, uint8Array))
      : Buffer.from(uint8Array).toString("base64");

  return base64String
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function bigintToUint8Array(bigint: bigint): Uint8Array {
  const length = Math.ceil(bigint.toString(2).length / 8);
  const buffer = new ArrayBuffer(length);
  const view = new DataView(buffer);

  for (let i = length - 1; i >= 0; i--) {
    view.setUint8(i, Number(bigint & 0xffn));
    bigint >>= 8n;
  }

  return new Uint8Array(buffer);
}

export default async function verifyWebAuthnSignature(
  signature: string,
  public_key: string
): Promise<boolean> {
  const sig = base58_to_binary(signature.replace("SIG_WA_", "")).slice(0, -4);
  const r = sig.slice(1, 33);
  const s = sig.slice(33, 65);

  const authenticatorData_len_bytes = [] as Array<number>;
  let authenticatorData_len_pos = 65;
  authenticatorData_len_bytes.push(sig[authenticatorData_len_pos]);
  do {
    authenticatorData_len_bytes.push(sig[authenticatorData_len_pos]);
    authenticatorData_len_pos += 1;
  } while (sig[authenticatorData_len_pos] & 0x80);

  const authenticatorData_len = decodeLEB128(authenticatorData_len_bytes);
  const authenticatorData = sig.slice(66, 66 + authenticatorData_len);

  const clientData_length_bytes = [] as Array<number>;
  let clientData_length_pos = 66 + authenticatorData_len;
  clientData_length_bytes.push(sig[clientData_length_pos]);

  do {
    clientData_length_pos += 1;
    clientData_length_bytes.push(sig[clientData_length_pos]);
  } while (sig[clientData_length_pos] & 0x80);
  const clientData_length = decodeLEB128(clientData_length_bytes);
  const clientDataJSON = sig.slice(-clientData_length);
  const clientDataHash = new Uint8Array(
    await sha256(new Uint8Array(clientDataJSON))
  );

  const signedData = new Uint8Array(
    authenticatorData.length + clientDataHash.length
  );

  signedData.set(authenticatorData);
  signedData.set(clientDataHash, authenticatorData.length);

  const prefix_x_coordinate = base58_to_binary(
    public_key.replace("PUB_WA_", "")
  );

  const x_array = prefix_x_coordinate.slice(1, 33);
  const prefix = prefix_x_coordinate[0];

  const y_array = bigintToUint8Array(
    calculateY(
      BigInt(
        x_array.reduce(
          (acc, i) => (acc += String(i.toString(16)).padStart(2, "0")),
          "0x"
        )
      ),
      prefix
    )
  );

  const x = base64UrlEncode(x_array);
  const y = base64UrlEncode(y_array);

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x, y },
    { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } },
    false,
    ["verify"]
  );

  return await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    key,
    Uint8Array.from([...r, ...s]),
    signedData.buffer
  );
}
