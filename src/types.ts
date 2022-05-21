import type { CipherGCMTypes } from "crypto";

export type JOSEHeader = {
  typ: "JWT";
  alg: HmacAlgo | RsaAlgo | EcdsaAlgo | RsaPssAlgo;
  enc?: Cipher;
};
export type AAData = {
  iv: string;
  ad: object | null;
};
type HmacAlgo = "HS256" | "HS384" | "HS512";
type RsaAlgo = "RS256" | "RS384" | "RS512";
type EcdsaAlgo = "ES256" | "ES384" | "ES512";
type RsaPssAlgo = "PS256" | "PS384" | "PS512";
type Cipher = CipherGCMTypes | "chacha20-poly1305";
