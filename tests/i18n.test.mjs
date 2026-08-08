import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  germanMessages,
  getAvailableLanguages,
  getLocale,
  getResolvedLanguage,
  translateText,
} from "../public/i18n.js";

test("supports explicit English and German language choices", () => {
  assert.equal(getResolvedLanguage("en"), "en");
  assert.equal(getResolvedLanguage("de"), "de");
});

test("discovers language metadata and catalogues from JSON", async () => {
  assert.deepEqual(getAvailableLanguages().map(({ code }) => code), ["en", "de"]);
  assert.equal(getLocale("de"), "de-DE");
  const registry = JSON.parse(await readFile(new URL("../public/locales/languages.json", import.meta.url), "utf8"));
  assert.equal(registry.defaultLanguage, "en");
  for (const language of registry.languages) {
    const catalogue = JSON.parse(await readFile(new URL(`../public/locales/${language.code}.json`, import.meta.url), "utf8"));
    assert.equal(typeof catalogue.Overview, "string");
  }
});

test("translates core navigation and security text to German", () => {
  assert.equal(translateText("Overview", "de"), "Übersicht");
  assert.equal(translateText("Two-factor authentication", "de"), "Zwei-Faktor-Authentifizierung");
  assert.equal(translateText("Overview", "en"), "Overview");
});

test("preserves whitespace and translates dynamic counters", () => {
  assert.equal(translateText("  3 resources  ", "de"), "  3 Ressourcen  ");
  assert.equal(translateText("Updated Aug 3, 2026", "de"), "Aktualisiert Aug 3, 2026");
  assert.equal(translateText("7m ago", "de"), "vor 7 Min.");
  assert.equal(translateText("3 running", "de"), "3 aktiv");
  assert.equal(translateText("0 conversations · newest activity first", "de"), "0 Unterhaltungen · neueste Aktivität zuerst");
  assert.equal(translateText("1 events", "de"), "1 Ereignis");
  assert.equal(translateText("5 node metrics · 3 storage paths", "de"), "Metriken von 5 Knoten · 3 Speicherpfade");
  assert.equal(translateText("0% of active accounts use 2FA", "de"), "0 % der aktiven Konten verwenden 2FA");
  assert.equal(translateText("of 2 protected", "de"), "von 2 geschützt");
});

test("ships a substantial German panel dictionary", () => {
  assert.ok(Object.keys(germanMessages).length >= 300);
});

test("uses a consistent globe icon for the system language preference", async () => {
  const [appSource, indexSource, stylesSource] = await Promise.all([
    readFile(new URL("../public/app.js", import.meta.url), "utf8"),
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/styles.css", import.meta.url), "utf8"),
  ]);

  assert.match(appSource, /const systemLanguageIcon = `<svg class="language-globe"/);
  assert.match(appSource, /getAvailableLanguages\(\)/);
  assert.doesNotMatch(appSource, /de:\s*\{\s*label:\s*"Deutsch"/);
  assert.doesNotMatch(appSource, /icon: "◎"/);
  assert.equal((indexSource.match(/class="language-globe"/g) || []).length, 2);
  assert.match(stylesSource, /\.language-globe \{/);
});
