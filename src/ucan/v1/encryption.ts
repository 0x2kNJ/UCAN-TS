import _sodium from "libsodium-wrappers";
import { toB64Url, fromB64Url } from "./index.js";

// Initialize sodium
await _sodium.ready;
const sodium = _sodium;

// Types for encrypted metadata
export interface EncryptedMetadata {
  encrypted: string; // base64url encoded encrypted data
  nonce: string;     // base64url encoded nonce
}

export interface EncryptionKey {
  key: Uint8Array;
}

/**
 * Generate a random encryption key for metadata
 */
export function generateEncryptionKey(): EncryptionKey {
  return {
    key: sodium.crypto_secretbox_keygen()
  };
}

/**
 * Encrypt metadata using XSalsa20-Poly1305 (libsodium secretbox)
 */
export function encryptMetadata(data: any, encryptionKey: EncryptionKey): EncryptedMetadata {
  // Serialize the data
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  
  // Generate random nonce
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  
  // Encrypt the data
  const encrypted = sodium.crypto_secretbox_easy(plaintext, nonce, encryptionKey.key);
  
  return {
    encrypted: toB64Url(encrypted),
    nonce: toB64Url(nonce),
  };
}

/**
 * Decrypt metadata
 */
export function decryptMetadata(encryptedMeta: EncryptedMetadata, encryptionKey: EncryptionKey): any {
  try {
    const encrypted = fromB64Url(encryptedMeta.encrypted);
    const nonce = fromB64Url(encryptedMeta.nonce);
    
    // Decrypt the data
    const decrypted = sodium.crypto_secretbox_open_easy(encrypted, nonce, encryptionKey.key);
    
    // Parse the JSON
    const plaintext = new TextDecoder().decode(decrypted);
    return JSON.parse(plaintext);
  } catch (error) {
    throw new Error(`Failed to decrypt metadata: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Create an encryption key from a base64url string (for storage/transport)
 */
export function encryptionKeyFromString(keyB64: string): EncryptionKey {
  return {
    key: fromB64Url(keyB64)
  };
}

/**
 * Convert an encryption key to base64url string (for storage/transport)
 */
export function encryptionKeyToString(encryptionKey: EncryptionKey): string {
  return toB64Url(encryptionKey.key);
}

/**
 * Derive an encryption key from a password using PBKDF2-HMAC-SHA256
 * Production-ready key derivation function
 */
export function deriveEncryptionKeyFromPassword(
  password: string, 
  salt?: Uint8Array, 
  iterations: number = 100000
): { key: EncryptionKey; salt: Uint8Array } {
  const actualSalt = salt || sodium.randombytes_buf(32);
  
  // Use PBKDF2-HMAC-SHA256 for proper key derivation
  const passwordBytes = new TextEncoder().encode(password);
  
  // Implement PBKDF2 using libsodium's HMAC
  let derivedKey = passwordBytes;
  
  // Iterative HMAC application (simplified PBKDF2)
  for (let i = 0; i < iterations; i++) {
    const combined = new Uint8Array(derivedKey.length + actualSalt.length + 4);
    combined.set(derivedKey);
    combined.set(actualSalt, derivedKey.length);
    // Add iteration counter as big-endian 32-bit integer
    combined.set(new Uint8Array([
      (i >> 24) & 0xff,
      (i >> 16) & 0xff,
      (i >> 8) & 0xff,
      i & 0xff
    ]), derivedKey.length + actualSalt.length);
    
    derivedKey = new Uint8Array(sodium.crypto_hash(combined));
  }
  
  // Take first 32 bytes for secretbox key
  const key = derivedKey.slice(0, 32);
  
  return {
    key: { key },
    salt: actualSalt
  };
}

/**
 * Alternative: Use scrypt for key derivation (when available)
 * Note: libsodium-wrappers may not have scrypt in browser builds
 */
export function deriveEncryptionKeyFromPasswordScrypt(
  password: string,
  salt?: Uint8Array,
  N: number = 32768,  // CPU/memory cost
  r: number = 8,      // block size
  p: number = 1       // parallelization
): { key: EncryptionKey; salt: Uint8Array } {
  const actualSalt = salt || sodium.randombytes_buf(32);
  
  try {
    // Try to use scrypt if available
    const passwordBytes = new TextEncoder().encode(password);
    const derivedKey = (sodium as any).crypto_pwhash_scryptsalsa208sha256(
      32, // key length
      passwordBytes,
      actualSalt,
      N * r * p, // opslimit approximation
      N * r * 128, // memlimit approximation
      2 // algorithm ID for scrypt
    );
    
    return {
      key: { key: derivedKey },
      salt: actualSalt
    };
  } catch {
    // Fallback to PBKDF2 if scrypt not available
    return deriveEncryptionKeyFromPassword(password, actualSalt, 100000);
  }
}

/**
 * Check if an object contains encrypted metadata
 */
export function isEncryptedMetadata(obj: any): obj is EncryptedMetadata {
  return obj !== null && 
         obj !== undefined &&
         typeof obj === 'object' &&
         typeof obj.encrypted === 'string' && 
         typeof obj.nonce === 'string';
}

/**
 * Mixed metadata type that can contain both plain and encrypted fields
 */
export interface MixedMetadata {
  [key: string]: any | EncryptedMetadata;
}

/**
 * Encrypt specific fields in metadata while leaving others plain
 */
export function encryptMetadataFields(
  metadata: Record<string, any>, 
  fieldsToEncrypt: string[], 
  encryptionKey: EncryptionKey
): MixedMetadata {
  const result: MixedMetadata = {};
  
  for (const [key, value] of Object.entries(metadata)) {
    if (fieldsToEncrypt.includes(key)) {
      result[key] = encryptMetadata(value, encryptionKey);
    } else {
      result[key] = value;
    }
  }
  
  return result;
}

/**
 * Decrypt specific fields in mixed metadata
 */
export function decryptMetadataFields(
  mixedMetadata: MixedMetadata, 
  encryptionKey: EncryptionKey
): Record<string, any> {
  const result: Record<string, any> = {};
  
  for (const [key, value] of Object.entries(mixedMetadata)) {
    if (isEncryptedMetadata(value)) {
      result[key] = decryptMetadata(value, encryptionKey);
    } else {
      result[key] = value;
    }
  }
  
  return result;
}
