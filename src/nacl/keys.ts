import { generateRandomBytes } from "../utils";
import { SECRET_BOX_KEY_LEN } from "./config";

export const generateSecretBoxKey = () => {
  return generateRandomBytes(SECRET_BOX_KEY_LEN);
};
