# Localization

Nimbus Direct keeps its language catalogue in `public/locales`. A contributor
does not need to edit application JavaScript to add a language.

## Files

- `languages.json` is the registry of available languages and selects the
  English fallback catalogue.
- `en.json` is the complete source catalogue and fallback.
- `de.json` is the German catalogue.
- `<code>.json` contains any additional language.

All catalogues are flat JSON objects. The English text on the left is the stable
message key; only translate the value on the right:

```json
{
  "Start": "Starten",
  "Stop": "Stoppen",
  "Always use {language}": "Immer {language} verwenden"
}
```

Keep placeholders such as `{language}`, `{count}`, and `{value}` unchanged.
Customer names, VM names, ticket messages, and other user-provided content are
never translated.

## Add a language

1. Copy `public/locales/en.json` to a BCP 47 language code such as
   `public/locales/fr.json`.
2. Translate the JSON values. Do not change the keys or placeholders.
3. Add one entry to `public/locales/languages.json`:

   ```json
   {
     "code": "fr",
     "name": "French",
     "nativeName": "Français",
     "locale": "fr-FR"
   }
   ```

4. Validate the contribution:

   ```bash
   pnpm locales:check
   pnpm check
   ```

The sign-in language button, Settings language cards, administrator email
language fields, browser-language detection, and API metadata discover the new
registry entry automatically. Missing messages fall back to English.

## Registry format

`defaultLanguage` must match one registered language. Each language entry must
contain a unique `code`, an English `name`, a `nativeName`, and an Intl-compatible
`locale`. The catalogue filename must exactly match `<code>.json`.

The validator rejects malformed catalogues, unregistered JSON files, duplicate
language codes, unknown keys, empty or non-string translations, missing or
renamed placeholders, and application copy that was not added to the English
source catalogue. Missing translations remain valid and fall back to English.

Every pull request that touches a catalogue or a localized backend template runs
the same validator in GitHub Actions. Its check summary includes a coverage table
for every registered language, while a broken placeholder fails the check and
prevents the contribution from being merged when the check is required by the
repository's branch protection.

Account, security, maintenance, support, infrastructure-alert, push, and in-app
notification messages use these catalogues too. A new language therefore does
not require a separate backend template or notification implementation.

## iOS catalogue

The iOS project consumes the same source files. From the sibling
`nimbus-direct-ios` directory, run:

```bash
node scripts/sync-locales.mjs
```

This generates the Xcode string catalogue and bundled language registry. The
generated files are committed with the app, so adding a language still requires
no Swift or Xcode-project edits.
