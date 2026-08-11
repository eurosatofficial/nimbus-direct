const token = new URLSearchParams(location.search).get("token");
const status = document.getElementById("sessionStatus");
const session = status.parentElement;
const output = document.getElementById("terminal");
const screen = document.getElementById("screen");
const countdown = document.getElementById("countdown");
const terminalTools = document.getElementById("terminalTools");
const graphicalTools = document.getElementById("graphicalTools");
const displaySettings = document.getElementById("displaySettings");
const virtualKeyboardInput = document.getElementById("virtualKeyboardInput");
let activeSocket = null;
let activeTerminal = null;
let activeRfb = null;
let disconnectConsole = () => {};
let releaseGraphicalModifiers = () => {};
let terminalConnected = false;
const textEncoder = new TextEncoder();

document.getElementById("closeButton").addEventListener("click", () => {
  releaseGraphicalModifiers();
  disconnectConsole();
  window.close();
});

function line(value, className = "") {
  const span = document.createElement("span");
  span.className = className;
  span.textContent = value;
  output.append(span, document.createElement("br"));
}

function websocketUrl(path) {
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${path}`;
}

function markDisconnected(message) {
  status.textContent = message;
  session.classList.remove("ready");
  terminalConnected = false;
  setConsoleConnectionState(false);
}

function setConsoleConnectionState(connected) {
  document.querySelectorAll("[data-requires-connection]").forEach((control) => {
    control.disabled = !connected;
  });
}

function updateFullscreenLabels() {
  document.querySelectorAll('[data-console-action="fullscreen"]').forEach((button) => {
    button.textContent = document.fullscreenElement ? "Exit fullscreen" : "Fullscreen";
  });
}

function installCommonConsoleActions() {
  setConsoleConnectionState(false);
  document.querySelectorAll('[data-console-action="fullscreen"]').forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        if (document.fullscreenElement) await document.exitFullscreen();
        else if (document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen();
        else status.textContent = "Fullscreen is not available in this browser";
      } catch {
        status.textContent = "Fullscreen could not be opened";
      }
    });
  });
  document.querySelectorAll('[data-console-action="disconnect"]').forEach((button) => {
    button.addEventListener("click", () => {
      releaseGraphicalModifiers();
      disconnectConsole();
    });
  });
  document.addEventListener("fullscreenchange", updateFullscreenLabels);
}

function byteLength(value) {
  return textEncoder.encode(value).byteLength;
}

function sendTerminalInput(value) {
  if (!terminalConnected || activeSocket?.readyState !== WebSocket.OPEN || !value) return;
  activeSocket.send(`0:${byteLength(value)}:${value}`);
}

function installTerminalTools() {
  terminalTools.hidden = false;
  document.getElementById("keyboardButton").addEventListener("click", () => activeTerminal?.focus());
  const keys = { escape: "\u001b", tab: "\t", interrupt: "\u0003" };
  terminalTools.querySelectorAll("[data-terminal-key]").forEach((button) => {
    button.addEventListener("click", () => {
      sendTerminalInput(keys[button.dataset.terminalKey]);
      activeTerminal?.focus();
    });
  });
  document.getElementById("pasteButton").addEventListener("click", async () => {
    try {
      sendTerminalInput(await navigator.clipboard.readText());
    } catch {
      status.textContent = "Tap the terminal and use the system Paste command";
    }
    activeTerminal?.focus();
  });
}

async function startTerminalConsole(data) {
  if (!data.credentials?.password || !data.credentials?.user) {
    throw new Error("The short-lived terminal credential is incomplete.");
  }
  const [{ Terminal }, { FitAddon }] = await Promise.all([
    import("/vendor/xterm/lib/xterm.mjs"),
    import("/vendor/xterm-fit/lib/addon-fit.mjs"),
  ]);
  output.textContent = "";
  output.classList.add("xterm-host");
  screen.setAttribute("aria-label", "Interactive terminal console");
  installTerminalTools();

  const terminal = new Terminal({
    cursorBlink: true,
    cursorStyle: "block",
    allowProposedApi: false,
    convertEol: false,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
    fontSize: matchMedia("(max-width: 620px)").matches ? 13 : 14,
    letterSpacing: 0,
    lineHeight: 1.15,
    // Large scrollback buffers are expensive in a mobile web view and do not
    // improve the live console itself. Keep enough useful history without
    // making sustained command output progressively slower.
    scrollback: matchMedia("(max-width: 620px)").matches ? 1500 : 3000,
    smoothScrollDuration: 0,
    theme: {
      background: "#06090f",
      foreground: "#d7dcec",
      cursor: "#7a84ff",
      cursorAccent: "#06090f",
      selectionBackground: "#39447a",
      black: "#0f1420",
      red: "#ff7079",
      green: "#3bd59d",
      yellow: "#e4b45f",
      blue: "#7a84ff",
      magenta: "#b991ff",
      cyan: "#62cadb",
      white: "#d7dcec",
      brightBlack: "#687189",
      brightWhite: "#f4f6ff",
    },
  });
  const fitAddon = new FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(output);
  activeTerminal = terminal;

  const socket = new WebSocket(websocketUrl(data.websocketUrl), "binary");
  activeSocket = socket;
  disconnectConsole = () => socket.close();
  socket.binaryType = "arraybuffer";
  let authBuffer = new Uint8Array();
  let resizeTimer;
  let renderFrame = 0;
  let renderBytes = 0;
  let renderQueue = [];
  const ping = setInterval(() => {
    if (socket.readyState === WebSocket.OPEN) socket.send("2");
  }, 30_000);

  const fit = () => {
    if (!terminal.element) return;
    fitAddon.fit();
  };
  const fitSoon = () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(fit, 75);
  };

  // xterm can receive dozens of small WebSocket messages for one screen
  // update. Render them once per display frame to reduce layout and canvas
  // overhead without delaying keyboard input sent in the opposite direction.
  const flushTerminal = () => {
    renderFrame = 0;
    if (!renderQueue.length) return;
    let payload;
    if (renderQueue.length === 1) {
      payload = renderQueue[0];
    } else {
      payload = new Uint8Array(renderBytes);
      let offset = 0;
      for (const chunk of renderQueue) {
        payload.set(chunk, offset);
        offset += chunk.length;
      }
    }
    renderQueue = [];
    renderBytes = 0;
    terminal.write(payload);
  };
  const queueTerminalWrite = (value) => {
    if (!value.length) return;
    renderQueue.push(value);
    renderBytes += value.length;
    if (!renderFrame) renderFrame = requestAnimationFrame(flushTerminal);
  };

  terminal.onData(sendTerminalInput);
  terminal.onResize(({ cols, rows }) => {
    if (terminalConnected && socket.readyState === WebSocket.OPEN) socket.send(`1:${cols}:${rows}:`);
  });
  window.addEventListener("resize", fitSoon, { passive: true });

  socket.addEventListener("open", () => {
    status.textContent = "Authenticating terminal";
    socket.send(`${data.credentials.user}:${data.credentials.password}\n`);
  });
  socket.addEventListener("message", (event) => {
    const incoming = event.data instanceof ArrayBuffer
      ? new Uint8Array(event.data)
      : new TextEncoder().encode(String(event.data));
    if (!terminalConnected) {
      const combined = new Uint8Array(authBuffer.length + incoming.length);
      combined.set(authBuffer);
      combined.set(incoming, authBuffer.length);
      authBuffer = combined;
      if (authBuffer.length < 2) return;
      if (authBuffer[0] !== 79 || authBuffer[1] !== 75) {
        markDisconnected("Terminal authentication failed");
        socket.close();
        return;
      }
      terminalConnected = true;
      setConsoleConnectionState(true);
      data.credentials.password = "";
      data.credentials.user = "";
      status.textContent = "Terminal connected";
      session.classList.add("ready");
      if (authBuffer.length > 2) queueTerminalWrite(authBuffer.slice(2));
      authBuffer = new Uint8Array();
      requestAnimationFrame(() => requestAnimationFrame(() => {
        fit();
        terminal.focus();
      }));
      return;
    }
    queueTerminalWrite(incoming);
  });
  socket.addEventListener("close", () => {
    clearInterval(ping);
    clearTimeout(resizeTimer);
    if (renderFrame) cancelAnimationFrame(renderFrame);
    flushTerminal();
    markDisconnected(terminalConnected ? "Terminal closed" : "Terminal connection failed");
  });
  socket.addEventListener("error", () => markDisconnected("Terminal connection lost"));
  fitSoon();
}

const DISPLAY_PREFERENCES_KEY = "nimbus-console-display-v1";

function loadDisplayPreferences() {
  const defaults = {
    fit: true,
    resizeRemote: matchMedia("(max-width: 900px)").matches,
    quality: "balanced",
  };
  try {
    const stored = JSON.parse(localStorage.getItem(DISPLAY_PREFERENCES_KEY));
    if (!stored || typeof stored !== "object") return defaults;
    return {
      fit: typeof stored.fit === "boolean" ? stored.fit : defaults.fit,
      resizeRemote: typeof stored.resizeRemote === "boolean" ? stored.resizeRemote : defaults.resizeRemote,
      quality: ["responsive", "balanced", "sharp"].includes(stored.quality) ? stored.quality : defaults.quality,
    };
  } catch {
    return defaults;
  }
}

function saveDisplayPreferences(preferences) {
  try {
    localStorage.setItem(DISPLAY_PREFERENCES_KEY, JSON.stringify(preferences));
  } catch {
    // The console still works when private browsing blocks local storage.
  }
}

function applyGraphicalDisplay(rfb, preferences) {
  const profiles = {
    responsive: { quality: 3, compression: 7 },
    balanced: { quality: 5, compression: 3 },
    sharp: { quality: 8, compression: 2 },
  };
  const profile = profiles[preferences.quality] || profiles.balanced;
  rfb.scaleViewport = preferences.fit;
  rfb.clipViewport = !preferences.fit;
  rfb.resizeSession = preferences.resizeRemote;
  rfb.qualityLevel = profile.quality;
  rfb.compressionLevel = profile.compression;
  screen.classList.toggle("actual-size", !preferences.fit);
}

function installGraphicalTools(rfb, KeyTable, Keysyms) {
  graphicalTools.hidden = false;
  const preferences = loadDisplayPreferences();
  const fitViewport = document.getElementById("fitViewport");
  const resizeRemoteDisplay = document.getElementById("resizeRemoteDisplay");
  const imageQuality = document.getElementById("imageQuality");
  const displaySettingsButton = document.getElementById("displaySettingsButton");
  const graphicalKeyboardButton = document.getElementById("graphicalKeyboardButton");
  const graphicalPasteButton = document.getElementById("graphicalPasteButton");
  const pressedModifiers = new Map();
  const modifierKeys = {
    control: { keysym: KeyTable.XK_Control_L, code: "ControlLeft" },
    alt: { keysym: KeyTable.XK_Alt_L, code: "AltLeft" },
    super: { keysym: KeyTable.XK_Super_L, code: "MetaLeft" },
  };
  const namedKeys = {
    tab: { keysym: KeyTable.XK_Tab, code: "Tab" },
    escape: { keysym: KeyTable.XK_Escape, code: "Escape" },
  };
  const keyboardKeys = {
    Backspace: { keysym: KeyTable.XK_BackSpace, code: "Backspace" },
    Enter: { keysym: KeyTable.XK_Return, code: "Enter" },
    Tab: { keysym: KeyTable.XK_Tab, code: "Tab" },
    Escape: { keysym: KeyTable.XK_Escape, code: "Escape" },
    Delete: { keysym: KeyTable.XK_Delete, code: "Delete" },
    Insert: { keysym: KeyTable.XK_Insert, code: "Insert" },
    Home: { keysym: KeyTable.XK_Home, code: "Home" },
    End: { keysym: KeyTable.XK_End, code: "End" },
    PageUp: { keysym: KeyTable.XK_Page_Up, code: "PageUp" },
    PageDown: { keysym: KeyTable.XK_Page_Down, code: "PageDown" },
    ArrowLeft: { keysym: KeyTable.XK_Left, code: "ArrowLeft" },
    ArrowRight: { keysym: KeyTable.XK_Right, code: "ArrowRight" },
    ArrowUp: { keysym: KeyTable.XK_Up, code: "ArrowUp" },
    ArrowDown: { keysym: KeyTable.XK_Down, code: "ArrowDown" },
  };

  fitViewport.checked = preferences.fit;
  resizeRemoteDisplay.checked = preferences.resizeRemote;
  imageQuality.value = preferences.quality;
  applyGraphicalDisplay(rfb, preferences);

  const focusRemote = () => rfb.focus({ preventScroll: true });
  const releaseModifiers = () => {
    for (const [name, key] of [...pressedModifiers].reverse()) {
      rfb.sendKey(key.keysym, key.code, false);
      const button = graphicalTools.querySelector(`[data-vnc-modifier="${name}"]`);
      button?.classList.remove("active");
      button?.setAttribute("aria-pressed", "false");
    }
    pressedModifiers.clear();
  };
  releaseGraphicalModifiers = releaseModifiers;

  const sendKey = (key, releaseAfter = true, refocus = true) => {
    rfb.sendKey(key.keysym, key.code);
    if (releaseAfter) releaseModifiers();
    if (refocus) focusRemote();
  };
  const sendText = (text, refocus = true) => {
    releaseModifiers();
    for (const character of Array.from(String(text)).slice(0, 4096)) {
      if (character === "\n" || character === "\r") rfb.sendKey(KeyTable.XK_Return, "Enter");
      else if (character === "\t") rfb.sendKey(KeyTable.XK_Tab, "Tab");
      else rfb.sendKey(Keysyms.lookup(character.codePointAt(0)));
    }
    if (refocus) focusRemote();
  };

  graphicalTools.querySelectorAll("[data-vnc-modifier]").forEach((button) => {
    button.addEventListener("click", () => {
      const name = button.dataset.vncModifier;
      const key = modifierKeys[name];
      if (pressedModifiers.has(name)) {
        rfb.sendKey(key.keysym, key.code, false);
        pressedModifiers.delete(name);
        button.classList.remove("active");
        button.setAttribute("aria-pressed", "false");
      } else {
        rfb.sendKey(key.keysym, key.code, true);
        pressedModifiers.set(name, key);
        button.classList.add("active");
        button.setAttribute("aria-pressed", "true");
      }
      focusRemote();
    });
  });
  graphicalTools.querySelectorAll("[data-vnc-key]").forEach((button) => {
    button.addEventListener("click", () => sendKey(namedKeys[button.dataset.vncKey]));
  });
  document.getElementById("ctrlAltDeleteButton").addEventListener("click", () => {
    releaseModifiers();
    rfb.sendCtrlAltDel();
    focusRemote();
  });

  graphicalKeyboardButton.addEventListener("click", () => {
    virtualKeyboardInput.value = "";
    virtualKeyboardInput.focus({ preventScroll: true });
  });
  virtualKeyboardInput.addEventListener("keydown", (event) => {
    const key = keyboardKeys[event.key];
    if (!key) return;
    event.preventDefault();
    sendKey(key, true, false);
  });
  virtualKeyboardInput.addEventListener("input", (event) => {
    const entered = event.data ?? virtualKeyboardInput.value;
    virtualKeyboardInput.value = "";
    if (entered) sendText(entered, false);
  });
  graphicalPasteButton.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) sendText(text);
    } catch {
      status.textContent = "Tap Keyboard and use the system Paste command";
      virtualKeyboardInput.focus({ preventScroll: true });
    }
  });

  displaySettingsButton.addEventListener("click", () => {
    displaySettings.hidden = !displaySettings.hidden;
    displaySettingsButton.setAttribute("aria-expanded", String(!displaySettings.hidden));
  });
  const updateDisplay = () => {
    preferences.fit = fitViewport.checked;
    preferences.resizeRemote = resizeRemoteDisplay.checked;
    preferences.quality = imageQuality.value;
    applyGraphicalDisplay(rfb, preferences);
    saveDisplayPreferences(preferences);
    focusRemote();
  };
  fitViewport.addEventListener("change", updateDisplay);
  resizeRemoteDisplay.addEventListener("change", updateDisplay);
  imageQuality.addEventListener("change", updateDisplay);
}

async function startGraphicalConsole(data) {
  output.remove();
  if (!data.credentials?.password) throw new Error("The short-lived console credential is missing.");
  const [{ default: RFB }, { default: KeyTable }, { default: Keysyms }] = await Promise.all([
    import("/vendor/novnc/core/rfb.js"),
    import("/vendor/novnc/core/input/keysym.js"),
    import("/vendor/novnc/core/input/keysymdef.js"),
  ]);
  const rfb = new RFB(screen, websocketUrl(data.websocketUrl), {
    shared: true,
    wsProtocols: ["binary"],
    credentials: { password: data.credentials.password },
  });
  activeRfb = rfb;
  installGraphicalTools(rfb, KeyTable, Keysyms);
  disconnectConsole = () => {
    releaseGraphicalModifiers();
    rfb.disconnect();
  };
  let credentialRetry = false;
  rfb.showDotCursor = true;
  rfb.viewOnly = false;
  rfb.addEventListener("connect", () => {
    data.credentials.password = "";
    status.textContent = "Graphical console connected";
    session.classList.add("ready");
    setConsoleConnectionState(true);
    activeRfb.focus({ preventScroll: true });
  });
  rfb.addEventListener("disconnect", (event) => {
    releaseGraphicalModifiers();
    markDisconnected(event.detail.clean ? "Console closed" : "Console connection lost");
  });
  rfb.addEventListener("securityfailure", (event) => markDisconnected(event.detail?.reason || "Console security negotiation failed"));
  rfb.addEventListener("credentialsrequired", () => {
    if (credentialRetry) {
      markDisconnected("Console authentication failed");
      return;
    }
    credentialRetry = true;
    status.textContent = "Authenticating console";
    rfb.sendCredentials({ password: data.credentials.password });
  });
}

async function initialize() {
  if (!token) throw new Error("The console launch token is missing.");
  const response = await fetch(`/api/v1/console/session/${encodeURIComponent(token)}`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  const data = await response.json();
  if (!response.ok) throw new Error("This console ticket has expired or is no longer authorized.");
  document.getElementById("resourceName").textContent = data.resource.name;
  document.getElementById("resourceMeta").textContent = `${data.resource.node} · ${data.resource.type.toUpperCase()} ${data.resource.vmid}`;
  document.getElementById("consoleType").textContent = data.console?.label || "Graphical console";
  session.classList.add("ready");
  status.textContent = data.demo ? "Demo console ready" : "Secure gateway ready";
  const timer = setInterval(() => {
    const remaining = Math.max(0, Math.ceil((data.expiresAt - Date.now()) / 1000));
    countdown.textContent = `${remaining}s`;
    if (!remaining) {
      clearInterval(timer);
      markDisconnected("Ticket expired");
    }
  }, 1000);

  output.textContent = "";
  if (data.demo) {
    line("Nimbus Direct secure console gateway", "purple");
    line("Assignment verified · console permission allowed", "green");
    line(`Connected to ${data.resource.node}/${data.resource.type}/${data.resource.vmid}`);
    line("");
    line("Ubuntu 24.04.2 LTS atlas-web-01 tty1");
    line("");
    line("atlas-web-01 login: nimbus-demo", "muted");
    line("Last login: Mon Jul 21 20:14:08 2026");
    line("nimbus-demo@atlas-web-01:~$ █", "green");
    return;
  }
  if (data.console?.type === "terminal") await startTerminalConsole(data);
  else await startGraphicalConsole(data);
}

installCommonConsoleActions();

window.addEventListener("pagehide", () => {
  releaseGraphicalModifiers();
  disconnectConsole();
});

initialize().catch((error) => {
  status.textContent = "Console unavailable";
  output.textContent = "";
  line(error.message, "muted");
});
