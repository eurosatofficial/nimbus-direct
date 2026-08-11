const STORAGE_KEY = "nimbus-direct-language";
const LANGUAGE_CODE = /^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$/i;

async function readJson(relativePath) {
  const url = new URL(relativePath, import.meta.url);
  if (url.protocol === "file:") {
    const { readFile } = await import("node:fs/promises");
    return JSON.parse(await readFile(url, "utf8"));
  }
  const response = await fetch(url, { cache: "no-store", credentials: "same-origin" });
  if (!response.ok) throw new Error(`Could not load ${url.pathname} (${response.status})`);
  return response.json();
}

function normalizeCode(value) {
  return String(value || "").trim().toLowerCase();
}

function validateRegistry(input) {
  if (!input || !Array.isArray(input.languages) || !input.languages.length) {
    throw new Error("locales/languages.json must contain at least one language");
  }
  const seen = new Set();
  const languages = input.languages.map((entry) => {
    const code = normalizeCode(entry?.code);
    if (!LANGUAGE_CODE.test(code) || seen.has(code)) {
      throw new Error(`Invalid or duplicate language code: ${entry?.code || "(empty)"}`);
    }
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
  const defaultLanguage = normalizeCode(input.defaultLanguage || "en");
  if (!seen.has(defaultLanguage)) throw new Error("defaultLanguage must reference an installed language");
  return Object.freeze({ defaultLanguage, languages: Object.freeze(languages) });
}

const registry = validateRegistry(await readJson("./locales/languages.json"));
const catalogues = new Map(await Promise.all(registry.languages.map(async (language) => {
  const messages = await readJson(`./locales/${language.code}.json`);
  if (!messages || Array.isArray(messages) || typeof messages !== "object") {
    throw new Error(`locales/${language.code}.json must be a JSON object`);
  }
  return [language.code, Object.freeze({ ...messages })];
})));
const supported = new Set(["system", ...registry.languages.map(({ code }) => code)]);

const originalText = new WeakMap();
const originalAttributes = new WeakMap();
let observer;

function browserLanguages() {
  if (typeof navigator === "undefined") return [registry.defaultLanguage];
  return navigator.languages?.length ? navigator.languages : [navigator.language || registry.defaultLanguage];
}

function storedPreference() {
  if (typeof localStorage === "undefined") return "system";
  return localStorage.getItem(STORAGE_KEY) || "system";
}

function translateTemplate(source, replacements, language) {
  let value = catalogues.get(language)?.[source]
    ?? catalogues.get(registry.defaultLanguage)?.[source]
    ?? source;
  Object.entries(replacements).forEach(([key, replacement]) => {
    value = value.replaceAll(`{${key}}`, String(replacement));
  });
  return value;
}

function directTranslation(source, language) {
  return catalogues.get(language)?.[source]
    ?? catalogues.get(registry.defaultLanguage)?.[source]
    ?? source;
}

export function getAvailableLanguages() {
  return registry.languages;
}

export function getDefaultLanguage() {
  return registry.defaultLanguage;
}

export function getLanguageMetadata(code) {
  const normalized = normalizeCode(code);
  return registry.languages.find((language) => language.code === normalized) || null;
}

export function getLanguagePreference() {
  const saved = normalizeCode(storedPreference()) || "system";
  return supported.has(saved) ? saved : "system";
}

export function getResolvedLanguage(preference = getLanguagePreference()) {
  const selected = normalizeCode(preference);
  if (selected !== "system" && supported.has(selected)) return selected;
  for (const browserLanguage of browserLanguages()) {
    const candidate = normalizeCode(browserLanguage);
    const exact = registry.languages.find(({ code }) => code === candidate);
    if (exact) return exact.code;
    const base = candidate.split("-")[0];
    const compatible = registry.languages.find(({ code }) => code === base || code.split("-")[0] === base);
    if (compatible) return compatible.code;
  }
  return registry.defaultLanguage;
}

export function getLocale(language = getResolvedLanguage()) {
  return getLanguageMetadata(language)?.locale || getLanguageMetadata(registry.defaultLanguage)?.locale || "en-US";
}

export function setLanguage(preference) {
  const normalized = normalizeCode(preference);
  const selected = supported.has(normalized) ? normalized : "system";
  if (typeof localStorage !== "undefined") localStorage.setItem(STORAGE_KEY, selected);
  if (typeof document !== "undefined") {
    document.documentElement.lang = getResolvedLanguage(selected);
    translateDocument();
  }
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("nimbuslanguagechange", {
      detail: { preference: selected, language: getResolvedLanguage(selected) },
    }));
  }
}

export function cycleLanguage() {
  const order = ["system", ...registry.languages.map(({ code }) => code)];
  setLanguage(order[(order.indexOf(getLanguagePreference()) + 1) % order.length]);
}

const pluralPhrases = [
  "active support tickets", "critical incidents", "active incidents", "active notices",
  "scheduled windows", "storage paths", "active keys", "recovery emails", "resources",
  "sessions", "users", "emails", "messages", "events", "keys", "snapshots", "clusters",
  "nodes", "tickets", "notifications", "assignments", "guests", "actions", "incidents",
  "policies", "accounts", "customers", "conversations", "unreads", "notices", "tasks",
  "requests", "cores", "passkeys", "registered passkeys",
];
const singularPhrases = new Map([
  ["policies", "policy"], ["conversations", "conversation"], ["unreads", "unread"],
  ["storage paths", "storage path"], ["active keys", "active key"],
  ["recovery emails", "recovery email"], ["active notices", "active notice"],
  ["scheduled windows", "scheduled window"], ["active support tickets", "active support ticket"],
  ["critical incidents", "critical incident"], ["active incidents", "active incident"],
  ["passkeys", "passkey"], ["registered passkeys", "registered passkey"],
]);

function translatePlural(value, language) {
  const coverage = value.match(/^(\d+)\s+nodes? metrics\s+·\s+(\d+)\s+storage paths?$/i);
  if (coverage) {
    return translateTemplate("{nodes} node metrics · {paths} storage paths", {
      nodes: coverage[1], paths: coverage[2],
    }, language);
  }
  const phrases = pluralPhrases.map((phrase) => phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
  const match = value.match(new RegExp(`^(\\d+)\\s+(${phrases})(.*)$`, "i"));
  if (!match) return null;
  let noun = match[2].toLowerCase();
  if (Number(match[1]) === 1) noun = singularPhrases.get(noun) || noun.replace(/s$/, "");
  let suffix = match[3] || "";
  suffix = suffix
    .replace(" · email enabled", ` · ${directTranslation("email enabled", language)}`)
    .replace(" · in-panel only", ` · ${directTranslation("in-panel only", language)}`)
    .replace(" · newest activity first", ` · ${directTranslation("newest activity first", language)}`);
  if (suffix === " waiting for support") {
    const key = Number(match[1]) === 1 ? "waiting for support" : "waiting for support (plural)";
    suffix = ` ${directTranslation(key, language)}`;
  }
  return `${match[1]} ${directTranslation(noun, language)}${suffix}`;
}

function translateDynamic(clean, language) {
  let match = clean.match(/^(\d+)([smhd]) ago$/);
  if (match) return translateTemplate(`{count}${match[2]} ago`, { count: match[1] }, language);

  for (const prefix of ["Updated", "Created", "Expires", "Loading", "Generated", "Health sampled"]) {
    if (clean.startsWith(`${prefix} `)) {
      return translateTemplate(`${prefix} {value}`, { value: clean.slice(prefix.length + 1) }, language);
    }
  }
  if (clean.startsWith("Last active ")) {
    const value = clean.slice(12).replace(" · Expires ", ` · ${directTranslation("Expires", language)} `);
    return translateTemplate("Last active {value}", { value }, language);
  }

  match = clean.match(/^(\d+)\s+(running|stopped|suspended)$/);
  if (match) return `${match[1]} ${directTranslation(match[2], language)}`;
  match = clean.match(/^Across\s+(\d+)\s+clusters?$/);
  if (match) return translateTemplate(Number(match[1]) === 1 ? "Across {count} cluster" : "Across {count} clusters", { count: match[1] }, language);
  if (clean.endsWith(" uptime")) return translateTemplate("{value} uptime", { value: clean.slice(0, -7) }, language);
  if (clean.endsWith(" waiting")) return translateTemplate("{value} waiting", { value: clean.slice(0, -8) }, language);

  match = clean.match(/^(\d+)% of active accounts use 2FA$/);
  if (match) return translateTemplate("{count}% of active accounts use 2FA", { count: match[1] }, language);
  match = clean.match(/^(\d+) of (\d+) protected$/);
  if (match) return translateTemplate("{count} of {total} protected", { count: match[1], total: match[2] }, language);
  match = clean.match(/^of (\d+) protected$/);
  if (match) return translateTemplate("of {total} protected", { total: match[1] }, language);
  match = clean.match(/^(\d+) failed tasks? · (\d+) stuck$/);
  if (match) return translateTemplate("{failed} failed tasks · {stuck} stuck", { failed: match[1], stuck: match[2] }, language);
  match = clean.match(/^(\d+)\s*\/\s*(\d+) online$/);
  if (match) return translateTemplate("{online} / {total} online", { online: match[1], total: match[2] }, language);
  match = clean.match(/^(\d+) total$/);
  if (match) return translateTemplate("{count} total", { count: match[1] }, language);
  match = clean.match(/^(.+) available · (.+) total$/);
  if (match) return translateTemplate("{available} available · {total} total", { available: match[1], total: match[2] }, language);

  if (clean.includes(" · Last active ")) {
    const [before, after] = clean.split(" · Last active ", 2);
    return `${before} · ${translateTemplate("Last active {value}", { value: translateText(after, language) }, language)}`;
  }
  match = clean.match(/^(.+) on (macOS|iOS|iPadOS|Android|Windows|Linux)$/);
  if (match) return translateTemplate("{client} on {platform}", { client: match[1], platform: match[2] }, language);
  match = clean.match(/^(\d+) cores?$/);
  if (match) return translateTemplate(Number(match[1]) === 1 ? "{count} core" : "{count} cores", { count: match[1] }, language);
  if (clean.startsWith("Appearance: ")) return translateTemplate("Appearance: {value}", { value: directTranslation(clean.slice(12), language) }, language);
  if (clean.startsWith("Language: ")) return translateTemplate("Language: {value}", { value: directTranslation(clean.slice(10), language) }, language);

  match = clean.match(/^(.+) of (.+)$/);
  if (match) return translateTemplate("{used} of {total}", { used: match[1], total: match[2] }, language);
  return null;
}

export function translateText(input, language = getResolvedLanguage()) {
  const value = String(input ?? "");
  const normalizedLanguage = supported.has(normalizeCode(language)) ? normalizeCode(language) : registry.defaultLanguage;
  if (normalizedLanguage === registry.defaultLanguage || !value.trim()) return value;
  const leading = value.match(/^\s*/)?.[0] || "";
  const trailing = value.match(/\s*$/)?.[0] || "";
  const clean = value.trim();
  const exact = catalogues.get(normalizedLanguage)?.[clean];
  const translated = exact ?? translatePlural(clean, normalizedLanguage) ?? translateDynamic(clean, normalizedLanguage);
  return translated ? `${leading}${translated}${trailing}` : value;
}

export function t(source, replacements = {}, language = getResolvedLanguage()) {
  let value = translateText(source, language);
  Object.entries(replacements).forEach(([key, replacement]) => {
    value = value.replaceAll(`{${key}}`, String(replacement));
  });
  return value;
}

function shouldSkip(node) {
  const parent = node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
  return !parent || parent.closest("script, style, code, pre, [data-no-i18n]");
}

function translateTextNode(node) {
  if (shouldSkip(node)) return;
  if (!originalText.has(node)) originalText.set(node, node.nodeValue);
  node.nodeValue = translateText(originalText.get(node));
}

function translateElementAttributes(element) {
  if (!(element instanceof Element) || shouldSkip(element)) return;
  const attributes = ["placeholder", "aria-label", "title"];
  let saved = originalAttributes.get(element);
  if (!saved) {
    saved = new Map();
    originalAttributes.set(element, saved);
  }
  attributes.forEach((name) => {
    if (!element.hasAttribute(name)) return;
    if (!saved.has(name)) saved.set(name, element.getAttribute(name));
    element.setAttribute(name, translateText(saved.get(name)));
  });
}

function translateRoot(root) {
  if (root.nodeType === Node.TEXT_NODE) {
    translateTextNode(root);
    return;
  }
  if (!(root instanceof Element || root instanceof Document)) return;
  if (root instanceof Element) translateElementAttributes(root);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    if (walker.currentNode.nodeType === Node.TEXT_NODE) translateTextNode(walker.currentNode);
    else translateElementAttributes(walker.currentNode);
  }
}

function observe() {
  observer?.observe(document.documentElement, {
    childList: true,
    subtree: true,
    characterData: true,
    attributes: true,
    attributeFilter: ["placeholder", "aria-label", "title"],
  });
}

export function translateDocument() {
  if (typeof document === "undefined") return;
  observer?.disconnect();
  document.documentElement.lang = getResolvedLanguage();
  translateRoot(document);
  observe();
}

export function installTranslationObserver() {
  if (typeof MutationObserver === "undefined" || observer) return;
  observer = new MutationObserver((mutations) => {
    observer.disconnect();
    mutations.forEach((mutation) => {
      if (mutation.type === "characterData") {
        originalText.set(mutation.target, mutation.target.nodeValue);
        translateTextNode(mutation.target);
      } else if (mutation.type === "attributes") {
        const saved = originalAttributes.get(mutation.target) || new Map();
        saved.set(mutation.attributeName, mutation.target.getAttribute(mutation.attributeName));
        originalAttributes.set(mutation.target, saved);
        translateElementAttributes(mutation.target);
      } else {
        mutation.addedNodes.forEach(translateRoot);
      }
    });
    observe();
  });
  translateDocument();
}

export function languageMessages(language) {
  return Object.freeze({ ...(catalogues.get(normalizeCode(language)) || {}) });
}

export const germanMessages = languageMessages("de");
