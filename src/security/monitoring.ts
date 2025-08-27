/**
 * Security monitoring and alerting system
 * Real-time threat detection and response
 */

export interface SecurityEvent {
  type: 'warning' | 'error' | 'critical';
  category: 'authentication' | 'authorization' | 'resource' | 'injection' | 'dos';
  message: string;
  source: string;
  timestamp: number;
  metadata?: Record<string, any>;
}

export interface ThreatPattern {
  name: string;
  description: string;
  indicators: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: 'log' | 'block' | 'alert';
}

// Real-time security monitoring
export class SecurityMonitor {
  private events: SecurityEvent[] = [];
  private patterns: ThreatPattern[] = [];
  private alertCallbacks: ((event: SecurityEvent) => void)[] = [];
  
  constructor() {
    this.initializeThreatPatterns();
    this.startCleanupTimer();
  }
  
  // Add security event
  addEvent(event: SecurityEvent): void {
    this.events.push(event);
    
    // Check for threat patterns
    this.checkThreatPatterns(event);
    
    // Trigger alerts for critical events
    if (event.type === 'critical') {
      this.triggerAlerts(event);
    }
    
    // Limit event history to prevent memory bloat
    if (this.events.length > 10000) {
      this.events = this.events.slice(-5000);
    }
  }
  
  // Register alert callback
  onAlert(callback: (event: SecurityEvent) => void): void {
    this.alertCallbacks.push(callback);
  }
  
  // Get recent events
  getRecentEvents(minutes: number = 60): SecurityEvent[] {
    const cutoff = Math.floor(Date.now() / 1000) - (minutes * 60);
    return this.events.filter(event => event.timestamp >= cutoff);
  }
  
  // Get events by category
  getEventsByCategory(category: SecurityEvent['category'], minutes: number = 60): SecurityEvent[] {
    return this.getRecentEvents(minutes).filter(event => event.category === category);
  }
  
  // Detect attack patterns
  detectAttackPatterns(): { pattern: string; confidence: number; events: SecurityEvent[] }[] {
    const attacks: { pattern: string; confidence: number; events: SecurityEvent[] }[] = [];
    const recentEvents = this.getRecentEvents(10); // Last 10 minutes
    
    // Brute force detection
    const authFailures = recentEvents.filter(e => 
      e.category === 'authentication' && e.message.includes('failed')
    );
    if (authFailures.length > 10) {
      attacks.push({
        pattern: 'brute_force',
        confidence: Math.min(authFailures.length / 20, 1.0),
        events: authFailures
      });
    }
    
    // DoS detection
    const dosEvents = recentEvents.filter(e => 
      e.category === 'dos' || e.message.includes('rate_limit')
    );
    if (dosEvents.length > 5) {
      attacks.push({
        pattern: 'denial_of_service',
        confidence: Math.min(dosEvents.length / 10, 1.0),
        events: dosEvents
      });
    }
    
    // Privilege escalation detection
    const privEvents = recentEvents.filter(e => 
      e.message.includes('privilege') || e.message.includes('escalation')
    );
    if (privEvents.length > 3) {
      attacks.push({
        pattern: 'privilege_escalation',
        confidence: Math.min(privEvents.length / 5, 1.0),
        events: privEvents
      });
    }
    
    return attacks;
  }
  
  // Generate security report
  generateSecurityReport(hours: number = 24): {
    summary: Record<string, number>;
    topSources: { source: string; count: number }[];
    criticalEvents: SecurityEvent[];
    attackPatterns: { pattern: string; confidence: number }[];
  } {
    const events = this.getRecentEvents(hours * 60);
    
    // Event summary by type
    const summary = events.reduce((acc, event) => {
      acc[event.type] = (acc[event.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    // Top sources
    const sourceCount = events.reduce((acc, event) => {
      acc[event.source] = (acc[event.source] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    const topSources = Object.entries(sourceCount)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([source, count]) => ({ source, count }));
    
    // Critical events
    const criticalEvents = events.filter(e => e.type === 'critical');
    
    // Attack patterns
    const attackPatterns = this.detectAttackPatterns()
      .map(({ pattern, confidence }) => ({ pattern, confidence }));
    
    return { summary, topSources, criticalEvents, attackPatterns };
  }
  
  private initializeThreatPatterns(): void {
    this.patterns = [
      {
        name: 'repeated_auth_failures',
        description: 'Multiple authentication failures from same source',
        indicators: ['authentication', 'failed'],
        severity: 'medium',
        action: 'alert'
      },
      {
        name: 'privilege_escalation_attempt',
        description: 'Attempt to escalate privileges',
        indicators: ['privilege', 'escalation', 'unauthorized'],
        severity: 'high',
        action: 'block'
      },
      {
        name: 'dos_attack',
        description: 'Denial of service attack pattern',
        indicators: ['rate_limit', 'excessive', 'resource'],
        severity: 'high',
        action: 'block'
      },
      {
        name: 'injection_attempt',
        description: 'Code or data injection attempt',
        indicators: ['injection', 'malformed', 'suspicious'],
        severity: 'critical',
        action: 'block'
      }
    ];
  }
  
  private checkThreatPatterns(event: SecurityEvent): void {
    // Prevent infinite recursion by not checking patterns for security_monitor events
    if (event.source === 'security_monitor') {
      return;
    }
    
    for (const pattern of this.patterns) {
      const matches = pattern.indicators.some(indicator => 
        event.message.toLowerCase().includes(indicator.toLowerCase())
      );
      
      if (matches) {
        const threatEvent: SecurityEvent = {
          type: 'warning',
          category: 'authorization',
          message: `Threat pattern detected: ${pattern.name}`,
          source: 'security_monitor',
          timestamp: Math.floor(Date.now() / 1000),
          metadata: { 
            pattern: pattern.name,
            originalEvent: event,
            severity: pattern.severity 
          }
        };
        
        if (pattern.severity === 'critical') {
          threatEvent.type = 'critical';
        }
        
        // Don't recursively add threat events
        this.events.push(threatEvent);
      }
    }
  }
  
  private triggerAlerts(event: SecurityEvent): void {
    for (const callback of this.alertCallbacks) {
      try {
        callback(event);
      } catch (error) {
        console.error('Alert callback failed:', error);
      }
    }
  }
  
  private startCleanupTimer(): void {
    // Clean up old events every hour
    setInterval(() => {
      const cutoff = Math.floor(Date.now() / 1000) - (24 * 60 * 60); // 24 hours
      this.events = this.events.filter(event => event.timestamp >= cutoff);
    }, 60 * 60 * 1000);
  }
}

// Global security monitor instance
export const securityMonitor = new SecurityMonitor();

// Convenience functions for common security events
export function logSecurityEvent(
  type: SecurityEvent['type'],
  category: SecurityEvent['category'],
  message: string,
  source: string,
  metadata?: Record<string, any>
): void {
  securityMonitor.addEvent({
    type,
    category,
    message,
    source,
    timestamp: Math.floor(Date.now() / 1000),
    metadata
  });
}

export function logAuthenticationFailure(source: string, reason: string): void {
  logSecurityEvent('warning', 'authentication', `Authentication failed: ${reason}`, source);
}

export function logAuthorizationViolation(source: string, violation: string): void {
  logSecurityEvent('error', 'authorization', `Authorization violation: ${violation}`, source);
}

export function logResourceExhaustion(source: string, resource: string): void {
  logSecurityEvent('warning', 'resource', `Resource exhaustion: ${resource}`, source);
}

export function logInjectionAttempt(source: string, attempt: string): void {
  logSecurityEvent('critical', 'injection', `Injection attempt: ${attempt}`, source);
}

export function logDosAttempt(source: string, details: string): void {
  logSecurityEvent('error', 'dos', `DoS attempt: ${details}`, source);
}
