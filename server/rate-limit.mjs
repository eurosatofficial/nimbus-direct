export class RateLimiter {
  constructor({ limit, windowMs }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.entries = new Map();
  }

  consume(key) {
    const now = Date.now();
    const current = this.entries.get(key);
    if (!current || current.resetAt <= now) {
      this.entries.set(key, { count: 1, resetAt: now + this.windowMs });
      return { allowed: true, remaining: this.limit - 1, retryAfter: 0 };
    }
    current.count += 1;
    if (this.entries.size > 10_000) {
      for (const [entryKey, entry] of this.entries) if (entry.resetAt <= now) this.entries.delete(entryKey);
    }
    return {
      allowed: current.count <= this.limit,
      remaining: Math.max(0, this.limit - current.count),
      retryAfter: Math.max(1, Math.ceil((current.resetAt - now) / 1000)),
    };
  }

  clear(key) {
    this.entries.delete(key);
  }
}
