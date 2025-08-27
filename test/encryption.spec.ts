import { describe, it, expect } from "vitest";
import {
  generateEncryptionKey,
  encryptMetadata,
  decryptMetadata,
  encryptionKeyFromString,
  encryptionKeyToString,
  deriveEncryptionKeyFromPassword,
  isEncryptedMetadata,
  encryptMetadataFields,
  decryptMetadataFields,
} from "../src/ucan/v1/encryption.js";

describe("UCAN v1 Encrypted Metadata", () => {
  it("generates and uses encryption keys", async () => {
    const key = generateEncryptionKey();
    expect(key.key).toBeInstanceOf(Uint8Array);
    expect(key.key.length).toBe(32); // 256-bit key
  });

  it("encrypts and decrypts simple data", async () => {
    const key = generateEncryptionKey();
    const originalData = { userId: "12345", role: "admin", timestamp: Date.now() };
    
    const encrypted = encryptMetadata(originalData, key);
    expect(encrypted.encrypted).toBeTypeOf("string");
    expect(encrypted.nonce).toBeTypeOf("string");
    expect(isEncryptedMetadata(encrypted)).toBe(true);
    
    const decrypted = decryptMetadata(encrypted, key);
    expect(decrypted).toEqual(originalData);
  });

  it("encrypts different data to different ciphertexts", async () => {
    const key = generateEncryptionKey();
    const data1 = { value: "secret1" };
    const data2 = { value: "secret2" };
    
    const encrypted1 = encryptMetadata(data1, key);
    const encrypted2 = encryptMetadata(data2, key);
    
    // Should be different due to random nonces
    expect(encrypted1.encrypted).not.toBe(encrypted2.encrypted);
    expect(encrypted1.nonce).not.toBe(encrypted2.nonce);
    
    // But should decrypt correctly
    expect(decryptMetadata(encrypted1, key)).toEqual(data1);
    expect(decryptMetadata(encrypted2, key)).toEqual(data2);
  });

  it("fails to decrypt with wrong key", async () => {
    const key1 = generateEncryptionKey();
    const key2 = generateEncryptionKey();
    const data = { secret: "sensitive data" };
    
    const encrypted = encryptMetadata(data, key1);
    
    expect(() => decryptMetadata(encrypted, key2)).toThrow("Failed to decrypt metadata");
  });

  it("converts keys to/from strings", async () => {
    const key = generateEncryptionKey();
    const keyString = encryptionKeyToString(key);
    const keyRestored = encryptionKeyFromString(keyString);
    
    expect(keyString).toBeTypeOf("string");
    expect(keyRestored.key).toEqual(key.key);
    
    // Test that restored key works
    const data = { test: "value" };
    const encrypted = encryptMetadata(data, key);
    const decrypted = decryptMetadata(encrypted, keyRestored);
    expect(decrypted).toEqual(data);
  });

  it("derives keys from passwords", async () => {
    const password = "my-secure-password";
    const { key: key1, salt } = deriveEncryptionKeyFromPassword(password);
    const { key: key2 } = deriveEncryptionKeyFromPassword(password, salt);
    
    // Same password + salt should give same key
    expect(key1.key).toEqual(key2.key);
    
    // Test encryption/decryption works
    const data = { sensitive: "info" };
    const encrypted = encryptMetadata(data, key1);
    const decrypted = decryptMetadata(encrypted, key2);
    expect(decrypted).toEqual(data);
  });

  it("encrypts specific fields in metadata", async () => {
    const key = generateEncryptionKey();
    const metadata = {
      publicInfo: "this is public",
      userId: "user123",
      secretData: { ssn: "123-45-6789", bankAccount: "secret-account" },
      timestamp: Date.now()
    };
    
    const mixedMetadata = encryptMetadataFields(
      metadata, 
      ["userId", "secretData"], 
      key
    );
    
    // Public fields should remain plain
    expect(mixedMetadata.publicInfo).toBe("this is public");
    expect(mixedMetadata.timestamp).toBe(metadata.timestamp);
    
    // Secret fields should be encrypted
    expect(isEncryptedMetadata(mixedMetadata.userId)).toBe(true);
    expect(isEncryptedMetadata(mixedMetadata.secretData)).toBe(true);
    
    // Decrypt and verify
    const decrypted = decryptMetadataFields(mixedMetadata, key);
    expect(decrypted).toEqual(metadata);
  });

  it("handles complex nested data structures", async () => {
    const key = generateEncryptionKey();
    const complexData = {
      user: {
        id: "user123",
        profile: {
          name: "John Doe",
          email: "john@example.com",
          preferences: {
            theme: "dark",
            notifications: true,
            privateSettings: {
              apiKey: "secret-api-key",
              tokens: ["token1", "token2"]
            }
          }
        }
      },
      metadata: {
        created: "2024-01-01",
        version: "1.0.0"
      }
    };
    
    const encrypted = encryptMetadata(complexData, key);
    const decrypted = decryptMetadata(encrypted, key);
    
    expect(decrypted).toEqual(complexData);
  });

  it("detects invalid encrypted metadata", async () => {
    expect(isEncryptedMetadata({})).toBe(false);
    expect(isEncryptedMetadata({ encrypted: "test" })).toBe(false);
    expect(isEncryptedMetadata({ nonce: "test" })).toBe(false);
    expect(isEncryptedMetadata({ encrypted: "test", nonce: "test" })).toBe(true);
    expect(isEncryptedMetadata(null)).toBe(false);
    expect(isEncryptedMetadata(undefined)).toBe(false);
    expect(isEncryptedMetadata("string")).toBe(false);
  });
});
