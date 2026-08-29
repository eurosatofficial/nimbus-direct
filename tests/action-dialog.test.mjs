import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("power-action cancellation controls cannot submit the confirmation form", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const form = html.match(/<form method="dialog" id="actionForm"[\s\S]*?<\/form>/)?.[0];
  assert.ok(form, "action confirmation form is missing");

  const closeButton = form.match(/<button[^>]*data-cancel-action[^>]*aria-label="Cancel action"[^>]*>/)?.[0];
  const cancelButton = form.match(/<button[^>]*data-cancel-action[^>]*>Cancel<\/button>/)?.[0];
  const confirmButton = form.match(/<button[^>]*id="confirmAction"[^>]*>Confirm<\/button>/)?.[0];
  assert.match(closeButton || "", /type="button"/);
  assert.match(cancelButton || "", /type="button"/);
  assert.match(confirmButton || "", /type="submit"/);
});

test("the shared action handler executes only from the explicit confirm button", async () => {
  const source = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const start = source.indexOf('els.actionForm.addEventListener("submit"');
  const end = source.indexOf('els.snapshotForm.addEventListener("submit"', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const handler = source.slice(start, end);

  const explicitGate = handler.indexOf("event.submitter !== els.confirmAction");
  const execution = handler.indexOf("await runAction(resource, action)");
  assert.ok(explicitGate >= 0, "explicit submitter gate is missing");
  assert.ok(execution > explicitGate, "action executes before the explicit-confirmation gate");
  assert.match(handler, /if \(!resource \|\| !action \|\| els\.confirmAction\.disabled\) return/);
  assert.match(handler, /els\.actionDialog\.close\("confirm"\)/);

  assert.match(source, /function cancelActionDialog\(\)[\s\S]*close\("cancel"\)/);
  assert.match(source, /event\.target === els\.actionDialog/);
  assert.match(source, /els\.actionDialog\.addEventListener\("close", clearPendingAction\)/);
});

