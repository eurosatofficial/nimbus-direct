import test from "node:test";
import assert from "node:assert/strict";
import { RateLimiter } from "../server/rate-limit.mjs";

test("separate email test limiters do not lock each other and settings save can clear connection attempts", () => {
  const connectionTests = new RateLimiter({ limit: 2, windowMs: 60_000 });
  const testMessages = new RateLimiter({ limit: 1, windowMs: 60_000 });
  const key = "admin-id:127.0.0.1";

  assert.equal(connectionTests.consume(key).allowed, true);
  assert.equal(connectionTests.consume(key).allowed, true);
  assert.equal(connectionTests.consume(key).allowed, false);
  assert.equal(testMessages.consume(key).allowed, true);

  connectionTests.clear(key);
  assert.equal(connectionTests.consume(key).allowed, true);
  assert.equal(testMessages.consume(key).allowed, false);
});
