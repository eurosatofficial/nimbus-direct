import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("normalized storage availability is honored by cards, details, and alerts", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const notifications = await readFile(new URL("../server/notifications.mjs", import.meta.url), "utf8");

  assert.match(app, /function storageUsageKnown\(resource\)/);
  assert.match(app, /escapeHtml\(storageSummary\(resource\)\)/);
  assert.match(app, /storageKnown \? `\$\{resource\.storageUsed\} GB` : "Unavailable"/);
  assert.match(notifications, /resource\.storageUsageAvailable !== false/);
  assert.match(notifications, /observable: storageUsageAvailable/);
  assert.match(notifications, /if \(definition\.observable === false\)/);
  assert.match(notifications, /condition: storageUsageAvailable && resource\.storage > 0/);
});
