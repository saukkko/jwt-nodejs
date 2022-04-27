import { createHmac } from "crypto";
import { JSONToBase64UrlString } from "./util.js";

/**
 *
 * @param header JOSE Header according to RFC 7519
 * @param payload JSON formatted payload
 * @param secret Secret used for signing.
 * @returns JWT
 */
export const signJWT = async (
  header: JOSEHeader,
  payload: Record<string, unknown>,
  secret: string
): Promise<string> => {
  return new Promise((resolve, reject) => {
    const data = [
      JSONToBase64UrlString(header),
      JSONToBase64UrlString(payload),
    ];

    try {
      let algo = Object.entries(hmacAlgos).find(
        (hmac) => header.alg === hmac[0]
      );
      if (algo) data.push(signWithHmac(algo[1], secret, data));

      // TODO: Implement everything and tidy up
      algo = Object.entries(rsaAlgos).find((rsa) => header.alg === rsa[0]);
      if (algo) throw new Error("RSA signing not yet implemented");

      algo = Object.entries(ecdsaAlgos).find(
        (ecdsa) => header.alg === ecdsa[0]
      );
      if (algo) throw new Error("ECDSA signing not yet implemented");

      algo = Object.entries(rsaPssAlgos).find(
        (rsaPss) => header.alg === rsaPss[0]
      );
      if (algo) throw new Error("RSAPSS signing not yet implemented");

      return resolve(data.join("."));
    } catch (err) {
      reject(err);
    }
    reject("Invalid algorithm");
  });
};

const signWithHmac = (algo: string, secret: string, data: string[]) => {
  const hmac = createHmac(algo, Buffer.from(secret, "base64"));
  hmac.update(data.join("."));

  return hmac.digest("base64url");
};

const hmacAlgos = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
};

const rsaAlgos = {
  RS256: "rsa-sha256",
  RS384: "rsa-sha384",
  RS512: "rsa-sha512",
};
const ecdsaAlgos = {
  ES256: "ecdsa256",
  ES384: "ecdsa384",
  ES512: "ecdsa512",
};
const rsaPssAlgos = {
  PS256: "unknown",
  PS384: "unknown",
  PS512: "unknown",
};

type JOSEHeader = {
  typ: "JWT";
  alg: HmacAlgos | RsaAlgos | EcdsaAlgos | RsaPssAlgos;
};
type HmacAlgos = "HS256" | "HS384" | "HS512";
type RsaAlgos = "RS256" | "RS384" | "RS512";
type EcdsaAlgos = "ES256" | "ES384" | "ES512";
type RsaPssAlgos = "PS256" | "PS384" | "PS512";
