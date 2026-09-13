import { base58Decode, base58Encode } from "./base58";

/**
 * did:key method (https://w3c-ccg.github.io/did-method-key/) restricted to
 * Ed25519. A did:key is self-certifying: the identifier itself IS the public
 * key, multicodec-tagged and multibase-encoded. No registry, ledger, or
 * external lookup is needed to resolve it — verification only needs the DID
 * string.
 *
 * Layout: base58btc( [0xed, 0x01] ++ ed25519-public-key-bytes ), prefixed
 * with the multibase "z" flag and the "did:key:" scheme.
 */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

export function publicKeyToDid(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  const tagged = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + publicKey.length);
  tagged.set(ED25519_MULTICODEC_PREFIX, 0);
  tagged.set(publicKey, ED25519_MULTICODEC_PREFIX.length);
  return `did:key:z${base58Encode(tagged)}`;
}

export function didToPublicKey(did: string): Uint8Array {
  const prefix = "did:key:z";
  if (!did.startsWith(prefix)) {
    throw new Error(`Unsupported DID method or encoding: ${did}`);
  }
  const tagged = base58Decode(did.slice(prefix.length));
  const [codec0, codec1] = tagged;
  if (codec0 !== ED25519_MULTICODEC_PREFIX[0] || codec1 !== ED25519_MULTICODEC_PREFIX[1]) {
    throw new Error(`DID does not use the Ed25519 multicodec: ${did}`);
  }
  const publicKey = tagged.slice(2);
  if (publicKey.length !== 32) throw new Error(`Malformed did:key public key length for ${did}`);
  return publicKey;
}

export function isValidDidKey(did: string): boolean {
  try {
    didToPublicKey(did);
    return true;
  } catch {
    return false;
  }
}
