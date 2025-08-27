import { toB64Url, fromB64Url, verifyEd25519 } from "./index.js";

// Enhanced DID Document structure
export interface DIDDocument {
  "@context"?: string[];
  id: string;
  verificationMethod: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  keyAgreement?: (string | VerificationMethod)[];
  capabilityInvocation?: (string | VerificationMethod)[];
  capabilityDelegation?: (string | VerificationMethod)[];
  service?: ServiceEndpoint[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
  publicKeyJwk?: any;
}

export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string | string[] | Record<string, any>;
}

// DID Resolution result
export interface DIDResolutionResult {
  "@context"?: string[];
  didDocument?: DIDDocument;
  didDocumentMetadata?: Record<string, any>;
  didResolutionMetadata?: Record<string, any>;
}

// DID Resolver interface
export interface DIDResolver {
  resolve(did: string): Promise<DIDResolutionResult>;
  supportedMethods(): string[];
}

// Enhanced did:key resolver
export class DidKeyResolver implements DIDResolver {
  supportedMethods(): string[] {
    return ["key"];
  }

  async resolve(did: string): Promise<DIDResolutionResult> {
    if (!did.startsWith("did:key:")) {
      throw new Error("Not a did:key DID");
    }

    try {
      const publicKeyB64 = this.didKeyEd25519PublicKeyB64Url(did);
      const publicKeyMultibase = this.publicKeyToMultibase(publicKeyB64);
      
      const verificationMethodId = `${did}#${publicKeyMultibase}`;
      
      const verificationMethod: VerificationMethod = {
        id: verificationMethodId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: publicKeyMultibase
      };

      const didDocument: DIDDocument = {
        "@context": [
          "https://www.w3.org/ns/did/v1",
          "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        id: did,
        verificationMethod: [verificationMethod],
        authentication: [verificationMethodId],
        assertionMethod: [verificationMethodId],
        capabilityDelegation: [verificationMethodId],
        capabilityInvocation: [verificationMethodId]
      };

      return {
        "@context": ["https://w3id.org/did-resolution/v1"],
        didDocument,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          contentType: "application/did+ld+json"
        }
      };
    } catch (error) {
      return {
        "@context": ["https://w3id.org/did-resolution/v1"],
        didDocument: undefined,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: "invalidDid",
          errorMessage: error instanceof Error ? error.message : String(error)
        }
      };
    }
  }

  private didKeyEd25519PublicKeyB64Url(did: string): string {
    if (!did.startsWith("did:key:z")) {
      throw new Error("Invalid did:key format");
    }
    const b58part = did.slice(9); // remove "did:key:z"
    try {
      const decoded = fromB64Url(b58part);
      
      if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
        throw new Error("Not an Ed25519 did:key");
      }
      
      const pk = decoded.slice(2);
      return toB64Url(pk);
    } catch (error) {
      throw new Error("Invalid did:key encoding");
    }
  }

  private publicKeyToMultibase(publicKeyB64: string): string {
    const publicKey = fromB64Url(publicKeyB64);
    // Ed25519 multicodec prefix: 0xed01 + public key
    const multicodecKey = new Uint8Array([0xed, 0x01, ...publicKey]);
    // z prefix for base58btc encoding
    return `z${toB64Url(multicodecKey).replace(/=/g, '')}`;
  }
}

// did:web resolver
export class DidWebResolver implements DIDResolver {
  private httpClient: (url: string) => Promise<any>;

  constructor(httpClient?: (url: string) => Promise<any>) {
    this.httpClient = httpClient || this.defaultHttpClient;
  }

  supportedMethods(): string[] {
    return ["web"];
  }

  async resolve(did: string): Promise<DIDResolutionResult> {
    if (!did.startsWith("did:web:")) {
      throw new Error("Not a did:web DID");
    }

    try {
      const domain = did.substring(8); // remove "did:web:"
      const path = domain.includes(":") 
        ? domain.replace(/:/g, "/")
        : domain;
      
      const url = `https://${path}/.well-known/did.json`;
      
      const didDocument = await this.httpClient(url);
      
      return {
        "@context": ["https://w3id.org/did-resolution/v1"],
        didDocument,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          contentType: "application/did+ld+json"
        }
      };
    } catch (error) {
      return {
        "@context": ["https://w3id.org/did-resolution/v1"],
        didDocument: undefined,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: "notFound",
          errorMessage: error instanceof Error ? error.message : String(error)
        }
      };
    }
  }

  private async defaultHttpClient(url: string): Promise<any> {
    // Simple fetch implementation
    if (typeof fetch !== "undefined") {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      return response.json();
    } else {
      // Node.js environment - would need node-fetch or similar
      throw new Error("HTTP client not available. Provide one in constructor.");
    }
  }
}

// Universal DID resolver
export class UniversalDIDResolver implements DIDResolver {
  private resolvers: Map<string, DIDResolver> = new Map();

  constructor() {
    // Register default resolvers
    this.register(new DidKeyResolver());
    this.register(new DidWebResolver());
  }

  register(resolver: DIDResolver): void {
    for (const method of resolver.supportedMethods()) {
      this.resolvers.set(method, resolver);
    }
  }

  supportedMethods(): string[] {
    return Array.from(this.resolvers.keys());
  }

  async resolve(did: string): Promise<DIDResolutionResult> {
    const method = this.extractMethod(did);
    const resolver = this.resolvers.get(method);
    
    if (!resolver) {
      return {
        "@context": ["https://w3id.org/did-resolution/v1"],
        didDocument: undefined,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: "methodNotSupported",
          errorMessage: `DID method '${method}' not supported`
        }
      };
    }

    return resolver.resolve(did);
  }

  private extractMethod(did: string): string {
    const parts = did.split(":");
    if (parts.length < 3 || parts[0] !== "did") {
      throw new Error("Invalid DID format");
    }
    return parts[1];
  }
}

// Utility functions for working with DID documents
export class DIDDocumentUtils {
  static findVerificationMethod(
    didDocument: DIDDocument, 
    methodId: string
  ): VerificationMethod | undefined {
    return didDocument.verificationMethod.find(vm => vm.id === methodId);
  }

  static findVerificationMethodByType(
    didDocument: DIDDocument, 
    type: string
  ): VerificationMethod[] {
    return didDocument.verificationMethod.filter(vm => vm.type === type);
  }

  static getPublicKeyBytes(verificationMethod: VerificationMethod): Uint8Array {
    if (verificationMethod.publicKeyMultibase) {
      // Remove 'z' prefix and decode
      const encoded = verificationMethod.publicKeyMultibase.slice(1);
      const decoded = fromB64Url(encoded);
      // Skip multicodec prefix (first 2 bytes for Ed25519)
      return decoded.slice(2);
    }
    
    if (verificationMethod.publicKeyBase58) {
      // Would need base58 decoder
      throw new Error("Base58 keys not yet supported");
    }
    
    if (verificationMethod.publicKeyJwk) {
      // Would need JWK handling
      throw new Error("JWK keys not yet supported");
    }
    
    throw new Error("No supported public key format found");
  }

  static async verifySignature(
    didDocument: DIDDocument,
    message: Uint8Array,
    signature: string,
    verificationMethodId?: string
  ): Promise<boolean> {
    let verificationMethod: VerificationMethod | undefined;
    
    if (verificationMethodId) {
      verificationMethod = this.findVerificationMethod(didDocument, verificationMethodId);
    } else {
      // Use first Ed25519 verification method
      const ed25519Methods = this.findVerificationMethodByType(didDocument, "Ed25519VerificationKey2020");
      verificationMethod = ed25519Methods[0];
    }
    
    if (!verificationMethod) {
      throw new Error("No suitable verification method found");
    }
    
    const publicKeyBytes = this.getPublicKeyBytes(verificationMethod);
    const publicKeyB64 = toB64Url(publicKeyBytes);
    
    return verifyEd25519(message, signature, publicKeyB64);
  }
}

// Export convenience function
export function createDIDResolver(): UniversalDIDResolver {
  return new UniversalDIDResolver();
}
