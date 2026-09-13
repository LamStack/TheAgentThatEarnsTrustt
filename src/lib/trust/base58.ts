/**
 * Base58 (Bitcoin alphabet) encode/decode, used for multibase "z" (base58-btc)
 * encoding of did:key identifiers.
 */
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ALPHABET_MAP: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) {
  ALPHABET_MAP[ALPHABET[i] as string] = i;
}

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  let digits = [0];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  // Leading zero bytes -> leading '1's
  let leadingZeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) leadingZeros++;

  let result = "";
  for (let i = 0; i < leadingZeros; i++) result += ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) {
    result += ALPHABET[digits[i] as number];
  }
  return result;
}

export function base58Decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array();

  let bytes = [0];
  for (let i = 0; i < str.length; i++) {
    const value = ALPHABET_MAP[str[i] as string];
    if (value === undefined) throw new Error(`Invalid base58 character: ${str[i]}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += (bytes[j] as number) * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  let leadingZeros = 0;
  for (let i = 0; i < str.length && str[i] === ALPHABET[0]; i++) leadingZeros++;

  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(new Uint8Array(leadingZeros).fill(0), 0);
  for (let i = 0; i < bytes.length; i++) {
    result[leadingZeros + (bytes.length - 1 - i)] = bytes[i] as number;
  }
  return result;
}
