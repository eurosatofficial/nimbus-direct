const token = new URLSearchParams(location.search).get("token");
const status = document.getElementById("sessionStatus");
const session = status.parentElement;
const terminal = document.getElementById("terminal");
const countdown = document.getElementById("countdown");
document.getElementById("closeButton").addEventListener("click", () => window.close());

function line(value, className = "") {
  const span = document.createElement("span");
  span.className = className;
  span.textContent = value;
  terminal.append(span, document.createElement("br"));
}

async function initialize() {
  if (!token) throw new Error("The console launch token is missing.");
  const response = await fetch(`/api/v1/console/session/${encodeURIComponent(token)}`, { credentials: "same-origin", headers: { Accept: "application/json" } });
  const data = await response.json();
  if (!response.ok) throw new Error("This console ticket has expired or is no longer authorized.");
  document.getElementById("resourceName").textContent = data.resource.name;
  document.getElementById("resourceMeta").textContent = `${data.resource.node} · ${data.resource.type.toUpperCase()} ${data.resource.vmid}`;
  session.classList.add("ready");
  status.textContent = data.demo ? "Demo console ready" : "Secure gateway ready";
  const timer = setInterval(() => {
    const remaining = Math.max(0, Math.ceil((data.expiresAt - Date.now()) / 1000));
    countdown.textContent = `${remaining}s`;
    if (!remaining) { clearInterval(timer); status.textContent = "Ticket expired"; session.classList.remove("ready"); }
  }, 250);

  terminal.textContent = "";
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
  } else {
    terminal.remove();
    if (!data.credentials?.password) throw new Error("The short-lived console credential is missing.");
    const { default: RFB } = await import("/vendor/novnc/core/rfb.js");
    const websocketUrl = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${data.websocketUrl}`;
    const rfb = new RFB(document.getElementById("screen"), websocketUrl, {
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
      status.textContent = "Console connected";
      session.classList.add("ready");
    });
    rfb.addEventListener("disconnect", (event) => { status.textContent = event.detail.clean ? "Console closed" : "Console connection lost"; session.classList.remove("ready"); });
    rfb.addEventListener("securityfailure", (event) => {
      status.textContent = event.detail?.reason || "Console security negotiation failed";
      session.classList.remove("ready");
    });
    rfb.addEventListener("credentialsrequired", () => {
      if (credentialRetry) {
        status.textContent = "Console authentication failed";
        session.classList.remove("ready");
        return;
      }
      credentialRetry = true;
      status.textContent = "Authenticating console";
      rfb.sendCredentials({ password: data.credentials.password });
    });
  }
}

initialize().catch((error) => {
  status.textContent = "Console unavailable";
  terminal.textContent = "";
  line(error.message, "muted");
});
