import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const consoleHtmlUrl = new URL("../public/console.html", import.meta.url);
const consoleScriptUrl = new URL("../public/console.js", import.meta.url);

test("graphical console exposes permission-safe noVNC controls", async () => {
  const [html, script] = await Promise.all([
    readFile(consoleHtmlUrl, "utf8"),
    readFile(consoleScriptUrl, "utf8"),
  ]);

  for (const control of [
    'data-vnc-modifier="control"',
    'data-vnc-modifier="alt"',
    'data-vnc-modifier="super"',
    'data-vnc-key="tab"',
    'data-vnc-key="escape"',
    'id="ctrlAltDeleteButton"',
    'id="graphicalKeyboardButton"',
    'id="graphicalPasteButton"',
    'id="displaySettings"',
    'data-console-action="fullscreen"',
    'data-console-action="disconnect"',
  ]) {
    assert.ok(html.includes(control), `missing console control: ${control}`);
  }

  assert.match(script, /rfb\.sendCtrlAltDel\(\)/);
  assert.match(script, /KeyTable\.XK_Super_L/);
  assert.match(script, /Keysyms\.lookup/);
  assert.match(script, /rfb\.scaleViewport = preferences\.fit/);
  assert.doesNotMatch(script, /\.machine(?:Shutdown|Reboot|Reset)\(/);
});

test("console actions remain connection-aware", async () => {
  const [html, script] = await Promise.all([
    readFile(consoleHtmlUrl, "utf8"),
    readFile(consoleScriptUrl, "utf8"),
  ]);

  assert.match(html, /data-console-action="disconnect" data-requires-connection/);
  assert.match(script, /setConsoleConnectionState\(false\)/);
  assert.match(script, /setConsoleConnectionState\(true\)/);
  assert.match(script, /releaseGraphicalModifiers\(\)/);
});
