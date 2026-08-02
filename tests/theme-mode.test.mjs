import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("appearance is applied before the panel stylesheet to avoid a color flash", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const scriptPosition = html.indexOf("/theme.js");
  const stylesheetPosition = html.indexOf("/styles.css");
  assert.ok(scriptPosition > 0);
  assert.ok(stylesheetPosition > scriptPosition);
  assert.match(html, /id="authAppearanceButton"/);
  assert.match(html, /id="appearanceButton"/);
});

test("appearance supports persistent system, light, and dark modes", async () => {
  const source = await readFile(new URL("../public/theme.js", import.meta.url), "utf8");
  assert.match(source, /\["system", "light", "dark"\]/);
  assert.match(source, /prefers-color-scheme: dark/);
  assert.match(source, /localStorage\.setItem\(storageKey, appearance\)/);
  assert.match(source, /document\.documentElement\.dataset\.theme = theme/);
  assert.match(source, /nimbusappearancechange/);
});

test("settings expose explicit appearance choices and charts use theme tokens", async () => {
  const [app, styles] = await Promise.all([
    readFile(new URL("../public/app.js", import.meta.url), "utf8"),
    readFile(new URL("../public/styles.css", import.meta.url), "utf8"),
  ]);
  assert.match(app, /data-appearance="\$\{mode\}"/);
  assert.match(app, /System.*Light.*Dark/s);
  assert.match(app, /getPropertyValue\("--chart-grid"\)/);
  assert.match(styles, /:root\[data-theme="dark"\]/);
  assert.match(styles, /\.appearance-options/);
});

test("dark appearance keeps support, security, and shared controls on accessible surfaces", async () => {
  const styles = await readFile(new URL("../public/styles.css", import.meta.url), "utf8");
  assert.match(styles, /--primary-fill:\s*#5965d9/);
  assert.match(styles, /--red-fill:\s*#c44853/);
  assert.match(styles, /:root\[data-theme="dark"\]\s+:is\(\s*\.support-summary span,\s*\.security-coverage,\s*\.policy-flow span/s);
  assert.match(styles, /:root\[data-theme="dark"\]\s+\.security-summary-grid strong/);
  assert.match(styles, /:root\[data-theme="dark"\]\s+\.support-thread-closed/);
  assert.match(styles, /:root\[data-theme="dark"\]\s+\.notice\s*\{\s*color:\s*var\(--body\)/);
  assert.match(styles, /:root\[data-theme="dark"\]\s+\.detail-metric-icon\.memory/);
});
