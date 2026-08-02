const token = new URLSearchParams(location.search).get("token");
const status = document.getElementById("sessionStatus");
const session = status.parentElement;
const output = document.getElementById("terminal");
const screen = document.getElementById("screen");
const countdown = document.getElementById("countdown");
const terminalTools = document.getElementById("terminalTools");
let activeSocket = null;
let activeTerminal = null;
let terminalConnected = false;

document.getElementById("closeButton").addEventListener("click", () => {
  activeSocket?.close();
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
}

function byteLength(value) {
  return new TextEncoder().encode(value).byteLength;
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
    scrollback: 5000,
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
  socket.binaryType = "arraybuffer";
  let authBuffer = new Uint8Array();
  let resizeTimer;
  const ping = setInterval(() => {
    if (socket.readyState === WebSocket.OPEN) socket.send("2");
  }, 30_000);

  const fit = () => {
    if (!terminal.element) return;
    fitAddon.fit();
  };
  const fitSoon = () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(fit, 100);
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
      data.credentials.password = "";
      data.credentials.user = "";
      status.textContent = "Terminal connected";
      session.classList.add("ready");
      if (authBuffer.length > 2) terminal.write(authBuffer.slice(2));
      authBuffer = new Uint8Array();
      requestAnimationFrame(() => requestAnimationFrame(() => {
        fit();
        terminal.focus();
      }));
      return;
    }
    terminal.write(incoming);
  });
  socket.addEventListener("close", () => {
    clearInterval(ping);
    clearTimeout(resizeTimer);
    markDisconnected(terminalConnected ? "Terminal closed" : "Terminal connection failed");
  });
  socket.addEventListener("error", () => markDisconnected("Terminal connection lost"));
  fitSoon();
}

async function startGraphicalConsole(data) {
  output.remove();
  if (!data.credentials?.password) throw new Error("The short-lived console credential is missing.");
  const { default: RFB } = await import("/vendor/novnc/core/rfb.js");
  const rfb = new RFB(screen, websocketUrl(data.websocketUrl), {
    shared: true,
    wsProtocols: ["binary"],
    credentials: { password: data.credentials.password },
  });
  let credentialRetry = false;
  rfb.scaleViewport = true;
  rfb.resizeSession = false;
  rfb.viewOnly = false;
  rfb.addEventListener("connect", () => {
    data.credentials.password = "";
    status.textContent = "Graphical console connected";
    session.classList.add("ready");
  });
  rfb.addEventListener("disconnect", (event) => markDisconnected(event.detail.clean ? "Console closed" : "Console connection lost"));
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
  }, 250);

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

window.addEventListener("pagehide", () => activeSocket?.close());

initialize().catch((error) => {
  status.textContent = "Console unavailable";
  output.textContent = "";
  line(error.message, "muted");
});
