export interface AesCbcInputs {
  key: Uint8Array;
  message: Uint8Array;
  iv?: Uint8Array;
}
