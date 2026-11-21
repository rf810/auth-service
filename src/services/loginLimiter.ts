/** One reserved login attempt. Exactly one settle call takes effect. */
export interface LoginAttempt {
  /** Correct password: clears the email's failure history. */
  succeed(): void;
  /** Wrong password (or unknown email): records a failure. */
  fail(): void;
  /** Verification threw: frees the slot without recording a failure. */
  release(): void;
}

/**
 * Limits failed login attempts per email within a sliding window.
 *
 * Callers reserve an attempt with begin() *before* verifying the password, so
 * concurrent requests for the same email see in-flight attempts and cannot all
 * slip past the limit while bcrypt is running. Expired failure records for
 * inactive emails are swept at most once per window.
 */
export class LoginLimiter {
  private failures = new Map<string, number[]>();
  private pending = new Map<string, number>();
  private lastSweep = 0;
  private maxFailures: number;
  private windowMs: number;

  constructor(maxFailures = 5, windowMs = 15 * 60 * 1000) {
    this.maxFailures = maxFailures;
    this.windowMs = windowMs;
  }

  /** Reserves an attempt, or returns null if the email is currently blocked. */
  begin(email: string, now = Date.now()): LoginAttempt | null {
    this.maybeSweep(now);
    const key = email.toLowerCase();
    const inFlight = this.pending.get(key) ?? 0;
    if (this.recent(key, now).length + inFlight >= this.maxFailures) return null;
    this.pending.set(key, inFlight + 1);

    let settled = false;
    const settle = (action: () => void) => {
      if (settled) return;
      settled = true;
      const left = (this.pending.get(key) ?? 1) - 1;
      if (left > 0) this.pending.set(key, left);
      else this.pending.delete(key);
      action();
    };
    return {
      succeed: () => settle(() => this.failures.delete(key)),
      fail: () =>
        settle(() => {
          const at = Date.now();
          this.failures.set(key, [...this.recent(key, at), at]);
        }),
      release: () => settle(() => {}),
    };
  }

  /** Number of emails with tracked state (for tests and monitoring). */
  get trackedEmails(): number {
    return new Set([...this.failures.keys(), ...this.pending.keys()]).size;
  }

  /** Removes every email whose failures have all left the window. */
  sweep(now = Date.now()): void {
    this.lastSweep = now;
    for (const key of [...this.failures.keys()]) this.recent(key, now);
  }

  private maybeSweep(now: number): void {
    if (now - this.lastSweep >= this.windowMs) this.sweep(now);
  }

  private recent(key: string, now: number): number[] {
    const recent = (this.failures.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (recent.length) this.failures.set(key, recent);
    else this.failures.delete(key);
    return recent;
  }
}
