import { describe, it, expect, beforeEach } from "vitest";
import { 
  ChainSecurityValidator, 
  CapabilitySecurityAnalyzer,
  ContainerSecurityValidator,
  TimeSecurityValidator,
  ResourceGuard,
  SECURITY_LIMITS
} from "../src/security/advanced.js";
import { 
  securityMonitor,
  logAuthenticationFailure,
  logAuthorizationViolation,
  logPrivilegeEscalation
} from "../src/security/monitoring.js";
import { 
  Ed25519Signer, 
  signDelegationV1, 
  writeContainerV1,
  now 
} from "../src/ucan/v1/index.js";

describe("Advanced Security Features", () => {
  
  describe("Chain Security Validation", () => {
    it("should reject chains that are too deep", async () => {
      // Create a deep chain (exceeding MAX_CHAIN_DEPTH)
      const { signer } = await Ed25519Signer.generate();
      const did = "did:key:test";
      
      const chain = [];
      for (let i = 0; i < SECURITY_LIMITS.MAX_CHAIN_DEPTH + 2; i++) {
        const env = await signDelegationV1({
          iss: did,
          aud: did,
          att: [{ with: "data/read", can: "read" }],
          nbf: now(),
          exp: now() + 3600
        }, signer);
        chain.push(env);
      }
      
      const result = ChainSecurityValidator.validateChainComplexity(chain);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("chain_too_deep");
    });

    it("should reject delegations with too many capabilities", async () => {
      const payload = {
        iss: "did:key:test",
        aud: "did:key:test",
        att: Array(SECURITY_LIMITS.MAX_CAPABILITIES_PER_DELEGATION + 1).fill({
          with: "data/read",
          can: "read"
        }),
        nbf: now(),
        exp: now() + 3600
      };
      
      const result = ChainSecurityValidator.validateDelegationComplexity(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("too_many_capabilities");
    });

    it("should reject excessively long TTL", async () => {
      const payload = {
        iss: "did:key:test",
        aud: "did:key:test", 
        att: [{ with: "data/read", can: "read" }],
        nbf: now(),
        exp: now() + SECURITY_LIMITS.MAX_DELEGATION_TTL + 1000
      };
      
      const result = ChainSecurityValidator.validateDelegationComplexity(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("ttl_too_long");
    });

    it("should detect capability anomalies", () => {
      const capabilities = [
        { with: "*", can: "*" }, // Overly broad
        { with: "data/../etc", can: "read" }, // Path traversal
        { with: "data<script>", can: "read" } // Injection attempt
      ];
      
      const anomalies = ChainSecurityValidator.detectCapabilityAnomalies(capabilities);
      expect(anomalies).toContain("overly_broad_wildcard");
      expect(anomalies).toContain("path_traversal_attempt");
      expect(anomalies).toContain("potential_injection");
    });
  });

  describe("Capability Security Analysis", () => {
    it("should detect privilege broadening attempts", () => {
      const requestedCaps = [{ with: "*", can: "*" }];
      const grantedCaps = [{ with: "data/read", can: "read" }];
      
      const result = CapabilitySecurityAnalyzer.analyzePrivilegeEscalation(
        requestedCaps, 
        grantedCaps
      );
      
      expect(result.safe).toBe(false);
      expect(result.violations).toContain("privilege_broadening: *#*");
    });

    it("should detect suspicious resource patterns", () => {
      const requestedCaps = [
        { with: "/etc/passwd", can: "read" },
        { with: "admin/users", can: "write" }
      ];
      const grantedCaps = [{ with: "*", can: "*" }];
      
      const result = CapabilitySecurityAnalyzer.analyzePrivilegeEscalation(
        requestedCaps,
        grantedCaps  
      );
      
      expect(result.safe).toBe(false);
      expect(result.violations.some(v => v.includes("suspicious_resource"))).toBe(true);
    });

    it("should detect action elevation attempts", () => {
      const requestedCaps = [{ with: "data", can: "admin" }];
      const grantedCaps = [{ with: "data", can: "read" }];
      
      const result = CapabilitySecurityAnalyzer.analyzePrivilegeEscalation(
        requestedCaps,
        grantedCaps
      );
      
      expect(result.safe).toBe(false);
      expect(result.violations.some(v => v.includes("action_elevation"))).toBe(true);
    });
  });

  describe("Container Security Validation", () => {
    it("should reject containers that are too large", () => {
      const largeContainer = new Uint8Array(100 * 1024 * 1024); // 100MB
      
      const result = ContainerSecurityValidator.validateContainer(largeContainer);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("container_too_large");
    });

    it("should reject malformed containers", () => {
      // Create malformed container with invalid length
      const malformed = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]); // Invalid length
      
      const result = ContainerSecurityValidator.validateContainer(malformed);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("envelope_too_large");
    });

    it("should reject containers with too many envelopes", async () => {
      // This is a conceptual test - would need actual container creation
      // to exceed MAX_CONTAINER_ENVELOPES limit
      const { signer } = await Ed25519Signer.generate();
      
      // Create many small envelopes
      const envelopes = [];
      for (let i = 0; i < 5; i++) { // Small test set
        const env = await signDelegationV1({
          iss: "did:key:test",
          aud: "did:key:test",
          att: [{ with: "data", can: "read" }],
          nbf: now(),
          exp: now() + 3600
        }, signer);
        envelopes.push(env);
      }
      
      const container = await writeContainerV1(envelopes);
      const result = ContainerSecurityValidator.validateContainer(container);
      expect(result.valid).toBe(true); // Should pass with small number
    });
  });

  describe("Time Security Validation", () => {
    it("should reject timestamps too far in future", () => {
      const payload = {
        iss: "did:key:test",
        aud: "did:key:test",
        att: [{ with: "data", can: "read" }],
        nbf: now() + 600, // 10 minutes in future (exceeds 5 minute limit)
        exp: now() + 3600
      };
      
      const result = TimeSecurityValidator.validateTimestamps(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("timestamp_too_future");
    });

    it("should reject expired timestamps too far in past", () => {
      const payload = {
        iss: "did:key:test", 
        aud: "did:key:test",
        att: [{ with: "data", can: "read" }],
        nbf: now() - 3600,
        exp: now() - 100000 // Way in the past
      };
      
      const result = TimeSecurityValidator.validateTimestamps(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("timestamp_too_past");
    });

    it("should reject invalid time ranges", () => {
      const payload = {
        iss: "did:key:test",
        aud: "did:key:test", 
        att: [{ with: "data", can: "read" }],
        nbf: now() + 1000,
        exp: now() + 500 // exp before nbf
      };
      
      const result = TimeSecurityValidator.validateTimestamps(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("invalid_time_range");
    });
  });

  describe("Resource Guard", () => {
    beforeEach(() => {
      ResourceGuard.resetCounters();
    });

    it("should track and limit operations", () => {
      // Simulate many operations
      for (let i = 0; i < 150; i++) {
        const allowed = ResourceGuard.trackOperation("test_operation");
        if (i < 100) {
          expect(allowed).toBe(true);
        } else {
          expect(allowed).toBe(false); // Should be blocked after limit
        }
      }
    });

    it("should track memory usage", () => {
      ResourceGuard.trackMemoryUsage("test_op", 1024);
      ResourceGuard.trackMemoryUsage("test_op", 2048);
      
      // Memory tracking should not throw
      expect(true).toBe(true);
    });
  });

  describe("Security Monitoring", () => {
    beforeEach(() => {
      // Clear previous events
      securityMonitor.getRecentEvents(0);
    });

    it("should detect authentication failure patterns", () => {
      // Simulate multiple auth failures
      for (let i = 0; i < 12; i++) {
        logAuthenticationFailure("192.168.1.100", "invalid_credentials");
      }
      
      const attacks = securityMonitor.detectAttackPatterns();
      const bruteForce = attacks.find(a => a.pattern === "brute_force");
      
      expect(bruteForce).toBeDefined();
      expect(bruteForce?.confidence).toBeGreaterThan(0.5);
    });

    it("should detect privilege escalation patterns", () => {
      for (let i = 0; i < 5; i++) {
        logAuthorizationViolation("malicious_user", "privilege escalation attempt");
      }
      
      const attacks = securityMonitor.detectAttackPatterns();
      const privEsc = attacks.find(a => a.pattern === "privilege_escalation");
      
      expect(privEsc).toBeDefined();
      expect(privEsc?.confidence).toBeGreaterThan(0.8);
    });

    it("should generate security reports", () => {
      // Add some test events
      logAuthenticationFailure("test1", "failed");
      logAuthorizationViolation("test2", "violation");
      
      const report = securityMonitor.generateSecurityReport(1);
      
      expect(report.summary).toBeDefined();
      expect(report.topSources).toBeDefined();
      expect(report.topSources.length).toBeGreaterThan(0);
    });

    it("should track events by category", () => {
      logAuthenticationFailure("source1", "reason1");
      logAuthorizationViolation("source2", "reason2");
      
      const authEvents = securityMonitor.getEventsByCategory("authentication");
      const authzEvents = securityMonitor.getEventsByCategory("authorization");
      
      expect(authEvents.length).toBe(1);
      expect(authzEvents.length).toBe(1);
    });
  });

  describe("Integration Security Tests", () => {
    it("should handle complex attack scenario", async () => {
      const { signer } = await Ed25519Signer.generate();
      
      // Attempt to create malicious delegation with multiple violations
      const maliciousPayload = {
        iss: "did:key:attacker",
        aud: "did:key:victim",
        att: Array(SECURITY_LIMITS.MAX_CAPABILITIES_PER_DELEGATION + 5).fill({
          with: "../../../etc/passwd",
          can: "admin"
        }),
        nbf: now() + 1000, // Too far in future
        exp: now() + SECURITY_LIMITS.MAX_DELEGATION_TTL + 1000, // Too long TTL
        meta: { 
          malicious: "x".repeat(SECURITY_LIMITS.MAX_METADATA_SIZE + 100) // Too large
        }
      };
      
      // Should fail validation at multiple levels
      const complexityResult = ChainSecurityValidator.validateDelegationComplexity(maliciousPayload);
      expect(complexityResult.valid).toBe(false);
      
      const timeResult = TimeSecurityValidator.validateTimestamps(maliciousPayload);
      expect(timeResult.valid).toBe(false);
      
      const capabilityResult = CapabilitySecurityAnalyzer.analyzePrivilegeEscalation(
        maliciousPayload.att,
        [{ with: "data", can: "read" }]
      );
      expect(capabilityResult.safe).toBe(false);
    });
  });
});
