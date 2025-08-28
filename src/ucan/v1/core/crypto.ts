import _sodium from "libsodium-wrappers";

export interface Ed25519Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array; // implementation-specific layout
}

export interface CryptoProvider {
  toB64Url(bytes: Uint8Array): string;
  fromB64Url(s: string): Uint8Array;
  ed25519KeypairFromSeed(seed32: Uint8Array): Promise<Ed25519Keypair>;
  ed25519KeypairRandom(): Promise<Ed25519Keypair>;
  ed25519Sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
  ed25519Verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
}

// Default provider: libsodium
class SodiumCryptoProvider implements CryptoProvider {
  private ready: Promise<void>;
  private sodium!: typeof _sodium;

  constructor() {
    this.ready = (async () => {
      await _sodium.ready;
      this.sodium = _sodium;
    })();
  }

  private async ensureReady() {
    await this.ready;
  }

  async ed25519KeypairFromSeed(seed32: Uint8Array): Promise<Ed25519Keypair> {
    await this.ensureReady();
    const kp = this.sodium.crypto_sign_seed_keypair(seed32);
    return { publicKey: kp.publicKey, privateKey: kp.privateKey };
  }

  async ed25519KeypairRandom(): Promise<Ed25519Keypair> {
    await this.ensureReady();
    const kp = this.sodium.crypto_sign_keypair();
    return { publicKey: kp.publicKey, privateKey: kp.privateKey };
  }

  async ed25519Sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    await this.ensureReady();
    return this.sodium.crypto_sign_detached(message, secretKey);
    
  }

  async ed25519Verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    await this.ensureReady();
    return this.sodium.crypto_sign_verify_detached(signature, message, publicKey);
  }

  toB64Url(bytes: Uint8Array): string {
    return _sodium.to_base64(bytes, _sodium.base64_variants.URLSAFE_NO_PADDING);
  }

  fromB64Url(s: string): Uint8Array {
    return _sodium.from_base64(s, _sodium.base64_variants.URLSAFE_NO_PADDING);
  }
}

export const cryptoProvider: CryptoProvider = new SodiumCryptoProvider();


