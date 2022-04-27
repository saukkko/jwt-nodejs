import { randomBytes } from "crypto";
import { signJWT } from "./sign.js";

const secret = randomBytes(256).toString("base64");
console.log("Secret:\n" + secret + "\n");

signJWT({ typ: "JWT", alg: "HS512" }, { foo: "bar" }, secret).then((data) =>
  console.log("Token:\n" + data + "\n")
);
