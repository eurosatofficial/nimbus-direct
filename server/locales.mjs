import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const LANGUAGE_CODE = /^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$/i;
const localeRoot = new URL("../public/locales/", import.meta.url);

function readJson(name) {
  return JSON.parse(readFileSync(new URL(name, localeRoot), "utf8"));
}

function normalizedCode(value) {
  return String(value || "").trim().toLowerCase();
}

function loadRegistry() {
  const source = readJson("languages.json");
  if (!source || !Array.isArray(source.languages) || !source.languages.length) {
    throw new Error("public/locales/languages.json must contain at least one language");
  }
  const seen = new Set();
  const languages = source.languages.map((entry) => {
    const code = normalizedCode(entry?.code);
    if (!LANGUAGE_CODE.test(code) || seen.has(code)) throw new Error(`Invalid or duplicate language code: ${entry?.code || "(empty)"}`);
    if (!String(entry?.name || "").trim() || !String(entry?.nativeName || "").trim()) {
      throw new Error(`Language ${code} requires name and nativeName`);
    }
    seen.add(code);
    return Object.freeze({
      code,
      name: String(entry.name).trim(),
      nativeName: String(entry.nativeName).trim(),
      locale: String(entry.locale || code).trim(),
    });
  });
  const defaultLanguage = normalizedCode(source.defaultLanguage || "en");
  if (!seen.has(defaultLanguage)) throw new Error("defaultLanguage must reference an installed language");
  return Object.freeze({ defaultLanguage, languages: Object.freeze(languages) });
}

export const languageRegistry = loadRegistry();
export const availableLanguages = languageRegistry.languages;
export const defaultLanguage = languageRegistry.defaultLanguage;
const supportedLanguages = new Set(availableLanguages.map(({ code }) => code));

export const languageCatalogues = new Map(availableLanguages.map((language) => {
  const messages = readJson(`${language.code}.json`);
  if (!messages || Array.isArray(messages) || typeof messages !== "object") {
    throw new Error(`public/locales/${language.code}.json must be a JSON object`);
  }
  return [language.code, Object.freeze({ ...messages })];
}));

export function isSupportedLanguage(value) {
  return supportedLanguages.has(normalizedCode(value));
}

export function normalizeLanguage(value, fallback = defaultLanguage) {
  const fallbackCode = supportedLanguages.has(normalizedCode(fallback)) ? normalizedCode(fallback) : defaultLanguage;
  const code = normalizedCode(value || fallbackCode);
  return supportedLanguages.has(code) ? code : null;
}

export function localeFor(language) {
  const code = normalizeLanguage(language) || defaultLanguage;
  return availableLanguages.find((entry) => entry.code === code)?.locale || code;
}

export function translate(language, source, replacements = {}) {
  const code = normalizeLanguage(language) || defaultLanguage;
  let value = languageCatalogues.get(code)?.[source]
    ?? languageCatalogues.get(defaultLanguage)?.[source]
    ?? source;
  Object.entries(replacements).forEach(([key, replacement]) => {
    value = value.replaceAll(`{${key}}`, String(replacement));
  });
  return value;
}

export const localeDirectory = fileURLToPath(localeRoot);
