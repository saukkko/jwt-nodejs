import { randomBytes, createCipheriv, createDecipheriv, scrypt } from "crypto";
import type {
  CipherGCM,
  DecipherGCM,
  CipherGCMTypes,
  ScryptOptions,
} from "crypto";
import {
  base64UrlStringToJSON,
  JSONToBase64UrlString,
  base64Encode,
  base64Decode,
  base64UrlEncode,
  base64UrlDecode,
} from "./util.js";
import type { AAData } from "./types.js";

const scryptOpts: ScryptOptions = { N: 1024, r: 4, p: 4 };
/**
 *
 * @param password password input to scrypt
 * @param data base64 encoded data to encrypt
 * @param additionalData additional data to include in authentication
 * @returns ciphertext
 */
export const encryptDataAEAD = async (
  password: string,
  data: string,
  additionalData?: object,
  cipherAlgo?: CipherGCMTypes | "chacha20-poly1305"
): Promise<string> => {
  const iv = randomBytes(12);
  const salt = randomBytes(32);
  const aad: AAData = {
    iv: iv.toString("base64"),
    ad: additionalData || null,
  };

  const keyLen =
    cipherAlgo === "aes-128-gcm" ? 16 : cipherAlgo === "aes-192-gcm" ? 24 : 32;
  let cipherText: Buffer;
  let cipher: CipherGCM;

  return new Promise((resolve, reject) => {
    try {
      scrypt(Buffer.from(password), salt, keyLen, scryptOpts, (err, key) => {
        if (err) return reject(err);
        if (!key) return reject(new Error("no key"));

        if (cipherAlgo === "chacha20-poly1305" || !cipherAlgo) {
          cipher = createCipheriv(
            "chacha20-poly1305",
            key,
            Buffer.from(aad.iv, "base64"),
            {
              authTagLength: 12,
            }
          );
        } else {
          cipher = createCipheriv(
            cipherAlgo,
            key,
            Buffer.from(aad.iv, "base64"),
            { authTagLength: 12 }
          );
        }

        cipher.setAAD(Buffer.from(JSONToBase64UrlString(aad)));

        cipherText = cipher.update(Buffer.from(data, "base64"));
        cipherText = Buffer.concat([cipherText, cipher.final()]);
        const outBuf = Buffer.concat([salt, cipherText]);

        resolve(
          [
            JSONToBase64UrlString(aad),
            JSONToBase64UrlString({ data: outBuf.toString("base64") }),
            cipher.getAuthTag().toString("base64url"),
          ].join(".")
        );
      });
    } catch (err) {
      reject(err);
    }
  });
};

/**
 *
 * @param password password to pass to scrypt
 * @param data data as text (e.g. base64)
 * @param cipherAlgo cipher algorithm
 * @returns {Promise<Buffer>} promise
 */
export const decryptDataAEAD = (
  password: string,
  data: string,
  cipherAlgo?: CipherGCMTypes | "chacha20-poly1305"
) => {
  let clearText: Buffer;

  return new Promise((resolve, reject) => {
    try {
      const [aadBase64, encData, tag] = data.split(".");

      const aad: AAData = base64UrlStringToJSON(aadBase64);
      const buf = Buffer.from(base64UrlStringToJSON(encData).data, "base64");
      const authTag = Buffer.from(tag, "base64url");

      const salt = Buffer.from(buf.slice(0, 32));
      const cipherText = Buffer.from(buf.slice(32));

      const iv = Buffer.from(aad.iv, "base64");

      const keyLen =
        cipherAlgo === "aes-128-gcm"
          ? 16
          : cipherAlgo === "aes-192-gcm"
          ? 24
          : 32;
      let decipher: DecipherGCM;

      scrypt(Buffer.from(password), salt, keyLen, scryptOpts, (err, key) => {
        if (err) return reject(err);
        if (!key) return reject(new Error("no key"));

        if (cipherAlgo === "chacha20-poly1305" || !cipherAlgo) {
          decipher = createDecipheriv("chacha20-poly1305", key, iv, {
            authTagLength: 12,
          });
        } else {
          decipher = createDecipheriv(cipherAlgo, key, iv, {
            authTagLength: 12,
          });
        }

        decipher.setAAD(Buffer.from(JSONToBase64UrlString(aad)));
        decipher.setAuthTag(authTag);

        clearText = decipher.update(cipherText);
        clearText = Buffer.concat([clearText, decipher.final()]);

        resolve(clearText);
      });
    } catch (err) {
      reject(err);
    }
  });
};
