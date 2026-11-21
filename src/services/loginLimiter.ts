/**
 * Tracks failed login attempts per email in memory and blocks further
 * attempts once a threshold is reached within a sliding window.
 */
export class LoginLimiter {
  private failures = new Map<string, number[]>();
  private maxFailures: number;
  private windowMs: number;

  constructor(maxFailures = 5, windowMs = 15 * 60 * 1000) {
    this.maxFailures = maxFailures;
    this.windowMs = windowMs;
  }

  isBlocked(email: string, now = Date.now()): boolean {
    return this.recent(email, now).length >= this.maxFailures;
  }

  recordFailure(email: string, now = Date.now()): void {
    const key = email.toLowerCase();
    this.failures.set(key, [...this.recent(key, now), now]);
  }

  reset(email: string): void {
    this.failures.delete(email.toLowerCase());
  }

  private recent(email: string, now: number): number[] {
    const key = email.toLowerCase();
    const recent = (this.failures.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (recent.length) this.failures.set(key, recent);
    else this.failures.delete(key);
    return recent;
  }
}
