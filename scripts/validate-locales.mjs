import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  availableLanguages,
  defaultLanguage,
  languageCatalogues,
  localeDirectory,
} from "../server/locales.mjs";

function placeholders(value) {
  const source = String(value);
  const braces = [...source.matchAll(/\{([a-zA-Z][a-zA-Z0-9_]*)\}/g)].map((match) => `named:${match[1]}`);
  const printf = [...source.matchAll(/%(?:\d+\$)?[-+0#]*\d*(?:\.\d+)?(?:ll|l|h)?([a-zA-Z@])/g)].map((match) => `printf:${match[1]}`);
  return [...braces, ...printf].sort();
}

const defaultCatalogue = languageCatalogues.get(defaultLanguage);
if (!defaultCatalogue || !Object.keys(defaultCatalogue).length) throw new Error("The default language catalogue is empty");

const listed = new Set(availableLanguages.map(({ code }) => `${code}.json`));
const files = (await readdir(localeDirectory)).filter((name) => name.endsWith(".json") && name !== "languages.json");
const unlisted = files.filter((name) => !listed.has(name));
if (unlisted.length) throw new Error(`Unlisted language catalogues: ${unlisted.join(", ")}`);

for (const language of availableLanguages) {
  const raw = await readFile(join(localeDirectory, `${language.code}.json`), "utf8");
  const catalogue = JSON.parse(raw);
  for (const [key, value] of Object.entries(catalogue)) {
    if (typeof value !== "string") throw new Error(`${language.code}.json: ${key} must contain a string`);
    const expected = placeholders(key);
    const actual = placeholders(value);
    if (expected.join("|") !== actual.join("|")) {
      throw new Error(`${language.code}.json: placeholder mismatch for ${JSON.stringify(key)}`);
    }
  }
  const translated = Object.keys(defaultCatalogue).filter((key) => Object.hasOwn(catalogue, key)).length;
  const coverage = Math.round((translated / Object.keys(defaultCatalogue).length) * 100);
  console.log(`${language.code}: ${translated}/${Object.keys(defaultCatalogue).length} messages (${coverage}% coverage)`);
}

console.log(`${availableLanguages.length} language catalogues are valid; default is ${defaultLanguage}.`);
