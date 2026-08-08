import { randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { connect as connectNet } from "node:net";
import { connect as connectTls } from "node:tls";
import { defaultLanguage, localeFor, normalizeLanguage } from "./locales.mjs";

const EMAIL_PATTERN = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;

function problem(message, code = "email_delivery_failed", status = 502) {
  return Object.assign(new Error(message), { code, status });
}

function oneLine(value, label, maxLength = 200) {
  const normalized = String(value || "").trim();
  if (!normalized || normalized.length > maxLength || /[\r\n]/.test(normalized)) {
    throw problem(`${label} is invalid`, "invalid_email_message", 400);
  }
  return normalized;
}

export function normalizeMailbox(value, label = "Email address") {
  const mailbox = String(value || "").trim().toLowerCase();
  if (!EMAIL_PATTERN.test(mailbox) || mailbox.length > 254 || /[\r\n]/.test(mailbox)) {
    throw problem(`${label} is invalid`, "invalid_email_address", 400);
  }
  return mailbox;
}

function encodeHeader(value) {
  const header = oneLine(value, "Email header", 998);
  return /^[\x20-\x7e]*$/.test(header)
    ? header
    : `=?UTF-8?B?${Buffer.from(header, "utf8").toString("base64")}?=`;
}

function displayMailbox(name, email) {
  const mailbox = normalizeMailbox(email);
  const displayName = String(name || "").trim();
  if (!displayName) return `<${mailbox}>`;
  return `${encodeHeader(displayName.replace(/["\\]/g, ""))} <${mailbox}>`;
}

function base64Lines(value) {
  return Buffer.from(String(value || ""), "utf8").toString("base64").match(/.{1,76}/g)?.join("\r\n") || "";
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  })[character]);
}

export function normalizeEmailLanguage(value) {
  return normalizeLanguage(value) || defaultLanguage;
}

function normalizeEmailTimeZone(value) {
  const timeZone = String(value || "UTC").trim();
  try {
    return new Intl.DateTimeFormat("en", { timeZone }).resolvedOptions().timeZone;
  } catch {
    return "UTC";
  }
}

function emailDate(value, language, timeZone = null) {
  const date = value instanceof Date ? value : new Date(value);
  const lang = normalizeEmailLanguage(language);
  if (lang === defaultLanguage && !timeZone) return date.toISOString();
  return new Intl.DateTimeFormat(localeFor(lang), {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit",
    timeZone: normalizeEmailTimeZone(timeZone), timeZoneName: "short",
  }).format(date);
}

const germanSecurityCopy = new Map([
  ["New sign-in to your account", "Neue Anmeldung bei Ihrem Konto"],
  ["A successful sign-in to your Nimbus Direct account was completed.", "Eine erfolgreiche Anmeldung bei Ihrem Nimbus-Direct-Konto wurde abgeschlossen."],
  ["A recovery code was used", "Ein Wiederherstellungscode wurde verwendet"],
  ["A one-time recovery code was used to sign in. Review your active sessions and regenerate codes if this was unexpected.", "Zur Anmeldung wurde ein einmaliger Wiederherstellungscode verwendet. Prüfen Sie Ihre aktiven Sitzungen und erzeugen Sie neue Codes, falls dies unerwartet war."],
  ["Your Nimbus Direct account is active", "Ihr Nimbus-Direct-Konto ist aktiv"],
  ["Your invitation was accepted and your private password was created.", "Ihre Einladung wurde angenommen und Ihr persönliches Passwort wurde erstellt."],
  ["Your password was reset", "Ihr Passwort wurde zurückgesetzt"],
  ["Your Nimbus Direct password was changed and every active session was signed out. Two-factor authentication remains enabled.", "Ihr Nimbus-Direct-Passwort wurde geändert und alle aktiven Sitzungen wurden abgemeldet. Die Zwei-Faktor-Authentifizierung bleibt aktiviert."],
  ["An administrator reset your Nimbus Direct password and signed out every active session. Contact your infrastructure provider if this was unexpected.", "Ein Administrator hat Ihr Nimbus-Direct-Passwort zurückgesetzt und alle aktiven Sitzungen abgemeldet. Kontaktieren Sie Ihren Infrastrukturanbieter, falls dies unerwartet war."],
  ["Two-factor authentication reset", "Zwei-Faktor-Authentifizierung zurückgesetzt"],
  ["An administrator reset two-factor authentication for your account. Your active sessions were signed out.", "Ein Administrator hat die Zwei-Faktor-Authentifizierung für Ihr Konto zurückgesetzt. Ihre aktiven Sitzungen wurden abgemeldet."],
  ["A new API key was created", "Ein neuer API-Schlüssel wurde erstellt"],
  ["Two-factor authentication enabled", "Zwei-Faktor-Authentifizierung aktiviert"],
  ["Authenticator-based two-factor authentication is now protecting your Nimbus Direct account.", "Eine Authenticator-basierte Zwei-Faktor-Authentifizierung schützt jetzt Ihr Nimbus-Direct-Konto."],
  ["Two-factor authentication disabled", "Zwei-Faktor-Authentifizierung deaktiviert"],
  ["Two-factor authentication was removed from your Nimbus Direct account.", "Die Zwei-Faktor-Authentifizierung wurde von Ihrem Nimbus-Direct-Konto entfernt."],
  ["New recovery codes generated", "Neue Wiederherstellungscodes erzeugt"],
  ["Your previous recovery codes are no longer valid. Store the new set somewhere safe.", "Ihre bisherigen Wiederherstellungscodes sind nicht mehr gültig. Bewahren Sie den neuen Satz an einem sicheren Ort auf."],
  ["Your password was changed", "Ihr Passwort wurde geändert"],
  ["Your Nimbus Direct password was changed and every active session was signed out.", "Ihr Nimbus-Direct-Passwort wurde geändert und alle aktiven Sitzungen wurden abgemeldet."],
]);

function localizeSecurityCopy(value, language) {
  if (normalizeEmailLanguage(language) !== "de") return String(value || "");
  const text = String(value || "");
  if (germanSecurityCopy.has(text)) return germanSecurityCopy.get(text);
  const apiKey = text.match(/^The API key “(.+)” was created for your Nimbus Direct account\. Revoke it immediately if you did not create it\.$/);
  if (apiKey) return `Der API-Schlüssel „${apiKey[1]}“ wurde für Ihr Nimbus-Direct-Konto erstellt. Widerrufen Sie ihn sofort, wenn Sie ihn nicht selbst erstellt haben.`;
  return text;
}

export function testEmailTemplate(settings, recipient, language = "en") {
  const lang = normalizeEmailLanguage(language);
  const de = lang === "de";
  const sentAt = new Date();
  const text = [
    de ? "Die E-Mail-Zustellung von Nimbus Direct funktioniert." : "Nimbus Direct email delivery is working.",
    "",
    de ? `Dieser Test wurde an ${recipient} gesendet.` : `This test was sent to ${recipient}.`,
    `${de ? "SMTP-Endpunkt" : "SMTP endpoint"}: ${settings.host}:${settings.port}`,
    `${de ? "Verschlüsselung" : "Encryption"}: ${settings.security === "tls" ? "TLS" : "STARTTLS"}`,
    `${de ? "Gesendet" : "Sent"}: ${emailDate(sentAt, lang)}`,
    "",
    de
      ? "Sie können diesen Zustellkanal jetzt für zukünftige Konto- und Infrastrukturbenachrichtigungen verwenden."
      : "You can now use this delivery channel for future account and infrastructure notifications.",
  ].join("\n");
  const html = `<!doctype html>
<html lang="${lang}"><body style="margin:0;background:#f4f6fb;color:#1d2740;font-family:Arial,sans-serif">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 14px;background:#f4f6fb">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;overflow:hidden;border:1px solid #e0e4ef;border-radius:18px;background:#ffffff">
        <tr><td style="padding:24px 28px;background:#11182a;color:#ffffff;font-size:20px;font-weight:700">nimbus <span style="color:#7580ff">direct</span></td></tr>
        <tr><td style="padding:34px 28px">
          <div style="display:inline-block;padding:7px 11px;border-radius:999px;background:#eaf8f2;color:#16865f;font-size:12px;font-weight:700">${de ? "Zustellung bestätigt" : "Delivery verified"}</div>
          <h1 style="margin:18px 0 10px;font-size:26px;line-height:1.25">${de ? "Ihr E-Mail-Kanal ist bereit." : "Your email channel is ready."}</h1>
          <p style="margin:0 0 22px;color:#667087;font-size:15px;line-height:1.65">${de ? "Nimbus Direct hat sich erfolgreich bei Ihrem SMTP-Server authentifiziert und diese Nachricht zugestellt." : "Nimbus Direct successfully authenticated with your SMTP server and delivered this message."}</p>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:separate;border-spacing:0 8px">
            <tr><td style="color:#8a93a8;font-size:12px">${de ? "Empfänger" : "Recipient"}</td><td align="right" style="font-size:13px;font-weight:700">${escapeHtml(recipient)}</td></tr>
            <tr><td style="color:#8a93a8;font-size:12px">${de ? "SMTP-Endpunkt" : "SMTP endpoint"}</td><td align="right" style="font-size:13px;font-weight:700">${escapeHtml(settings.host)}:${Number(settings.port)}</td></tr>
            <tr><td style="color:#8a93a8;font-size:12px">${de ? "Verschlüsselung" : "Encryption"}</td><td align="right" style="font-size:13px;font-weight:700">${settings.security === "tls" ? "TLS" : "STARTTLS"}</td></tr>
          </table>
        </td></tr>
        <tr><td style="padding:18px 28px;border-top:1px solid #edf0f5;color:#929aad;font-size:11px">${de ? "Gesendet von Nimbus Direct am" : "Sent by Nimbus Direct at"} ${escapeHtml(emailDate(sentAt, lang))}</td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
  return {
    subject: de ? "Nimbus Direct – Test der E-Mail-Zustellung" : "Nimbus Direct email delivery test",
    text,
    html,
  };
}

export function securityEmailTemplate({ displayName, title, message, ipAddress = null, occurredAt = new Date(), language = "en" }) {
  const lang = normalizeEmailLanguage(language);
  const de = lang === "de";
  const name = String(displayName || (de ? "" : "there")).trim();
  const safeTitle = oneLine(localizeSecurityCopy(title, lang), "Security email title", 160);
  const safeMessage = oneLine(localizeSecurityCopy(message, lang), "Security email message", 500);
  const time = occurredAt instanceof Date ? occurredAt : new Date(occurredAt);
  const text = [
    de ? `Hallo${name ? ` ${name}` : ""},` : `Hello ${name},`,
    "",
    safeTitle,
    safeMessage,
    "",
    `${de ? "Zeit" : "Time"}: ${emailDate(time, lang)}`,
    ipAddress ? `${de ? "IP-Adresse" : "IP address"}: ${ipAddress}` : null,
    "",
    de
      ? "Wenn Sie diese Änderung nicht vorgenommen haben, kontaktieren Sie sofort Ihren Infrastrukturanbieter und ändern Sie Ihr Nimbus-Direct-Passwort."
      : "If you did not make this change, contact your infrastructure provider immediately and change your Nimbus Direct password.",
  ].filter((line) => line !== null).join("\n");
  const html = `<!doctype html>
<html lang="${lang}"><body style="margin:0;background:#f4f6fb;color:#1d2740;font-family:Arial,sans-serif">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 14px;background:#f4f6fb">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;overflow:hidden;border:1px solid #e0e4ef;border-radius:18px;background:#ffffff">
        <tr><td style="padding:24px 28px;background:#11182a;color:#ffffff;font-size:20px;font-weight:700">nimbus <span style="color:#7580ff">direct</span></td></tr>
        <tr><td style="padding:34px 28px">
          <div style="display:inline-block;padding:7px 11px;border-radius:999px;background:#eef0ff;color:#5662dc;font-size:12px;font-weight:700">${de ? "Kontosicherheit" : "Account security"}</div>
          <h1 style="margin:18px 0 10px;font-size:26px;line-height:1.25">${escapeHtml(safeTitle)}</h1>
          <p style="margin:0 0 22px;color:#667087;font-size:15px;line-height:1.65">${de ? `Hallo${name ? ` ${escapeHtml(name)}` : ""},` : `Hello ${escapeHtml(name)},`} ${escapeHtml(safeMessage)}</p>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:separate;border-spacing:0 8px">
            <tr><td style="color:#8a93a8;font-size:12px">${de ? "Zeit" : "Time"}</td><td align="right" style="font-size:13px;font-weight:700">${escapeHtml(emailDate(time, lang))}</td></tr>
            ${ipAddress ? `<tr><td style="color:#8a93a8;font-size:12px">${de ? "IP-Adresse" : "IP address"}</td><td align="right" style="font-size:13px;font-weight:700">${escapeHtml(ipAddress)}</td></tr>` : ""}
          </table>
          <div style="margin-top:24px;padding:15px 16px;border-radius:12px;background:#fff4e8;color:#8a531d;font-size:13px;line-height:1.55">${de ? "Wenn Sie diese Änderung nicht vorgenommen haben, kontaktieren Sie sofort Ihren Infrastrukturanbieter und ändern Sie Ihr Nimbus-Direct-Passwort." : "If you did not make this change, contact your infrastructure provider immediately and change your Nimbus Direct password."}</div>
        </td></tr>
        <tr><td style="padding:18px 28px;border-top:1px solid #edf0f5;color:#929aad;font-size:11px">${de ? "Automatische Sicherheitsbenachrichtigung von Nimbus Direct" : "Automatic security notice from Nimbus Direct"}</td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
  return { subject: `Nimbus Direct: ${safeTitle}`, text, html };
}

export function maintenanceEmailTemplate({ displayName, event, appUrl = "", language = "en" }) {
  const lang = normalizeEmailLanguage(language);
  const de = lang === "de";
  const name = String(displayName || (de ? "" : "there")).trim();
  const title = oneLine(event?.title, "Maintenance title", 160);
  const message = String(event?.message || "").trim();
  if (!message || message.length > 4000) throw problem("Maintenance message is invalid", "invalid_email_message", 400);
  const kind = event?.kind === "incident"
    ? (de ? "Servicestörung" : "Service incident")
    : (de ? "Geplante Wartung" : "Planned maintenance");
  const status = ["scheduled", "active", "resolved", "cancelled"].includes(event?.status) ? event.status : "scheduled";
  const startsAt = new Date(event?.startsAt);
  const endsAt = status === "resolved" && event?.resolvedAt
    ? new Date(event.resolvedAt)
    : event?.endsAt ? new Date(event.endsAt) : null;
  if (!Number.isFinite(startsAt.getTime()) || (endsAt && !Number.isFinite(endsAt.getTime()))) {
    throw problem("Maintenance schedule is invalid", "invalid_email_message", 400);
  }
  const timeZone = normalizeEmailTimeZone(event?.timeZone || "UTC");
  const safeAppUrl = appUrl ? oneLine(appUrl, "Panel URL", 2048) : "";
  const statusLabel = status === "resolved" ? (de ? "Behoben" : "Resolved")
    : status === "active" ? (de ? "In Bearbeitung" : "In progress")
      : status === "cancelled" ? (de ? "Abgesagt" : "Cancelled")
        : (de ? "Geplant" : "Scheduled");
  const subject = `${statusLabel}: ${title}`;
  const germanLocks = {
    power_management: "Energiesteuerung",
    console_access: "Konsolenzugriff",
    snapshot_management: "Snapshot-Änderungen",
    installation_media: "ISO- und CD-ROM-Vorgänge",
  };
  const lockLabels = ["scheduled", "active"].includes(status) && Array.isArray(event?.lockGroups)
    ? event.lockGroups.map((group) => oneLine(de ? (germanLocks[group?.id] || group?.label || group) : (group?.label || group), "Maintenance lock", 80))
    : [];
  const lockSummary = lockLabels.length
    ? (de
      ? `Nimbus schränkt während dieses Zeitfensters vorübergehend folgende Funktionen ein: ${lockLabels.join(", ")}. Der schreibgeschützte Zugriff bleibt verfügbar.`
      : `Nimbus will temporarily restrict these controls during the window: ${lockLabels.join(", ")}. Read-only access remains available.`)
    : "";
  const text = [
    de ? `Hallo${name ? ` ${name}` : ""},` : `Hello ${name},`,
    "",
    `${kind} — ${statusLabel}`,
    title,
    message,
    "",
    `${de ? "Beginn" : "Starts"}: ${emailDate(startsAt, lang, timeZone)}`,
    endsAt
      ? `${status === "resolved" ? statusLabel : (de ? "Ende" : "Ends")}: ${emailDate(endsAt, lang, timeZone)}`
      : `${de ? "Ende" : "Ends"}: ${de ? "Bis auf Weiteres" : "Until further notice"}`,
    lockSummary || null,
    safeAppUrl ? `${de ? "Wartungsstatus anzeigen" : "View maintenance status"}: ${safeAppUrl}` : null,
    "",
    de
      ? "Diese Benachrichtigung gilt ausschließlich für Infrastruktur, die Ihrem Nimbus-Direct-Kundenkonto zugewiesen ist."
      : "This notice applies only to infrastructure assigned to your Nimbus Direct customer account.",
  ].filter((line) => line !== null).join("\n");
  const accent = status === "resolved" ? "#16865f"
    : event?.severity === "critical" ? "#c94747"
      : event?.severity === "warning" ? "#a56825"
        : "#5662dc";
  const soft = status === "resolved" ? "#eaf8f2"
    : event?.severity === "critical" ? "#fff0f0"
      : event?.severity === "warning" ? "#fff4e8"
        : "#eef0ff";
  const htmlMessage = escapeHtml(message).replace(/\r?\n/g, "<br>");
  const htmlLockSummary = lockSummary
    ? `<div style="margin-top:18px;padding:14px 16px;border-radius:12px;background:#fff4e8;color:#8a531d;font-size:13px;line-height:1.55"><strong>${de ? "Vorübergehende Aktionssperre" : "Temporary action lock"}</strong><br>${escapeHtml(lockSummary)}</div>`
    : "";
  const action = safeAppUrl
    ? `<table role="presentation" cellspacing="0" cellpadding="0" style="margin-top:22px"><tr><td style="border-radius:10px;background:#5b67e8"><a href="${escapeHtml(safeAppUrl)}" style="padding:13px 20px;display:inline-block;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700">${de ? "Wartungsstatus anzeigen" : "View maintenance status"}</a></td></tr></table>`
    : "";
  const html = `<!doctype html>
<html lang="${lang}"><body style="margin:0;background:#f4f6fb;color:#1d2740;font-family:Arial,sans-serif">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 14px;background:#f4f6fb">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;overflow:hidden;border:1px solid #e0e4ef;border-radius:18px;background:#ffffff">
        <tr><td style="padding:24px 28px;background:#11182a;color:#ffffff;font-size:20px;font-weight:700">nimbus <span style="color:#7580ff">direct</span></td></tr>
        <tr><td style="padding:34px 28px">
          <div style="display:inline-block;padding:7px 11px;border-radius:999px;background:${soft};color:${accent};font-size:12px;font-weight:700">${escapeHtml(kind)} · ${escapeHtml(statusLabel)}</div>
          <h1 style="margin:18px 0 10px;font-size:26px;line-height:1.25">${escapeHtml(title)}</h1>
          <p style="margin:0 0 22px;color:#667087;font-size:15px;line-height:1.65">${de ? `Hallo${name ? ` ${escapeHtml(name)}` : ""},` : `Hello ${escapeHtml(name)},`}<br>${htmlMessage}</p>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:separate;border-spacing:0 8px">
            <tr><td style="color:#8a93a8;font-size:12px">${de ? "Beginn" : "Starts"}</td><td align="right" style="font-size:13px;font-weight:700">${escapeHtml(emailDate(startsAt, lang, timeZone))}</td></tr>
            <tr><td style="color:#8a93a8;font-size:12px">${status === "resolved" ? statusLabel : (de ? "Ende" : "Ends")}</td><td align="right" style="font-size:13px;font-weight:700">${endsAt ? escapeHtml(emailDate(endsAt, lang, timeZone)) : (de ? "Bis auf Weiteres" : "Until further notice")}</td></tr>
          </table>
          ${htmlLockSummary}
          ${action}
          <div style="margin-top:22px;padding:14px 16px;border-radius:12px;background:#f7f8fb;color:#717b90;font-size:12px;line-height:1.55">${de ? "Diese Benachrichtigung gilt ausschließlich für Infrastruktur, die Ihrem Nimbus-Direct-Kundenkonto zugewiesen ist." : "This notice applies only to infrastructure assigned to your Nimbus Direct customer account."}</div>
        </td></tr>
        <tr><td style="padding:18px 28px;border-top:1px solid #edf0f5;color:#929aad;font-size:11px">${de ? "Automatische Wartungsnachricht von Nimbus Direct" : "Automatic maintenance message from Nimbus Direct"}</td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
  return { subject, text, html };
}

export function supportTicketEmailTemplate({
  displayName,
  ticket,
  message,
  actorName,
  eventType = "reply",
  appUrl = "",
  language = "en",
}) {
  const lang = normalizeEmailLanguage(language);
  const de = lang === "de";
  const name = String(displayName || (de ? "" : "there")).trim();
  const reference = oneLine(ticket?.reference, "Ticket reference", 80);
  const ticketSubject = oneLine(ticket?.subject, "Ticket subject", 160);
  const actor = oneLine(actorName || (de ? "Nimbus-Direct-Support" : "Nimbus Direct support"), "Ticket author", 160);
  const body = String(message || "").trim();
  if (!body || body.length > 8000) throw problem("Ticket message is invalid", "invalid_email_message", 400);
  const safeAppUrl = appUrl ? oneLine(appUrl, "Panel URL", 2048) : "";
  const isNew = eventType === "created";
  const isStatus = eventType === "status";
  const heading = isNew
    ? (de ? "Eine neue Supportanfrage wartet." : "A new support request is waiting.")
    : isStatus
      ? (de ? "Ihr Supportticket wurde aktualisiert." : "Your support ticket was updated.")
      : (de ? "Ihr Supportticket hat eine neue Antwort." : "Your support ticket has a new reply.");
  const subject = `[${reference}] ${isNew
    ? (de ? "Neue Supportanfrage" : "New support request")
    : isStatus ? (de ? "Ticket aktualisiert" : "Ticket updated") : (de ? "Neue Antwort" : "New reply")}: ${ticketSubject}`;
  const statusLabels = {
    open: de ? "Offen" : "open",
    waiting_support: de ? "Wartet auf Support" : "waiting support",
    waiting_customer: de ? "Wartet auf Kunden" : "waiting customer",
    resolved: de ? "Gelöst" : "resolved",
    closed: de ? "Geschlossen" : "closed",
  };
  const statusLabel = statusLabels[ticket?.status] || String(ticket?.status || "open").replaceAll("_", " ");
  const text = [
    de ? `Hallo${name ? ` ${name}` : ""},` : `Hello ${name},`,
    "",
    heading,
    `${reference} — ${ticketSubject}`,
    `${actor}:`,
    body,
    "",
    `Status: ${statusLabel}`,
    safeAppUrl ? `${de ? "Dieses Supportticket öffnen" : "Open this support ticket"}: ${safeAppUrl}` : null,
    "",
    de
      ? "Antworten Sie innerhalb von Nimbus Direct, damit die vollständige Unterhaltung geschützt und nachvollziehbar bleibt."
      : "Reply inside Nimbus Direct so the complete conversation remains protected and auditable.",
  ].filter((line) => line !== null).join("\n");
  const action = safeAppUrl
    ? `<table role="presentation" cellspacing="0" cellpadding="0" style="margin-top:22px"><tr><td style="border-radius:10px;background:#5b67e8"><a href="${escapeHtml(safeAppUrl)}" style="padding:13px 20px;display:inline-block;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700">${de ? "Supportticket öffnen" : "Open support ticket"}</a></td></tr></table>`
    : "";
  const htmlBody = escapeHtml(body).replace(/\r?\n/g, "<br>");
  const html = `<!doctype html>
<html lang="${lang}"><body style="margin:0;background:#f4f6fb;color:#1d2740;font-family:Arial,sans-serif">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 14px;background:#f4f6fb">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;overflow:hidden;border:1px solid #e0e4ef;border-radius:18px;background:#ffffff">
        <tr><td style="padding:24px 28px;background:#11182a;color:#ffffff;font-size:20px;font-weight:700">nimbus <span style="color:#7580ff">direct</span></td></tr>
        <tr><td style="padding:34px 28px">
          <div style="display:inline-block;padding:7px 11px;border-radius:999px;background:#eef0ff;color:#5662dc;font-size:12px;font-weight:700">Support · ${escapeHtml(reference)}</div>
          <h1 style="margin:18px 0 10px;font-size:26px;line-height:1.25">${escapeHtml(heading)}</h1>
          <p style="margin:0;color:#667087;font-size:15px;line-height:1.65">${de ? `Hallo${name ? ` ${escapeHtml(name)}` : ""},` : `Hello ${escapeHtml(name)},`}</p>
          <div style="margin-top:20px;padding:18px;border:1px solid #e5e8f0;border-radius:12px;background:#f9fafe">
            <strong style="display:block;margin-bottom:8px;color:#323c54;font-size:14px">${escapeHtml(ticketSubject)}</strong>
            <span style="display:block;margin-bottom:8px;color:#8a93a8;font-size:11px;font-weight:700">${escapeHtml(actor)}</span>
            <div style="color:#566078;font-size:14px;line-height:1.65">${htmlBody}</div>
          </div>
          ${action}
          <div style="margin-top:22px;padding:14px 16px;border-radius:12px;background:#f7f8fb;color:#717b90;font-size:12px;line-height:1.55">${de ? "Antworten Sie innerhalb von Nimbus Direct, damit die vollständige Unterhaltung geschützt und nachvollziehbar bleibt. Senden Sie keine Proxmox-Zugangsdaten in einem Ticket." : "Reply inside Nimbus Direct so the complete conversation remains protected and auditable. Do not send Proxmox credentials in a ticket."}</div>
        </td></tr>
        <tr><td style="padding:18px 28px;border-top:1px solid #edf0f5;color:#929aad;font-size:11px">${de ? "Automatische Supportnachricht von Nimbus Direct" : "Automatic support message from Nimbus Direct"}</td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
  return { subject, text, html };
}

function accountActionEmailTemplate({
  displayName,
  subject,
  badge,
  title,
  message,
  actionLabel,
  actionUrl,
  expiresAt,
  ignoreMessage,
  language = "en",
}) {
  const lang = normalizeEmailLanguage(language);
  const de = lang === "de";
  const name = String(displayName || (de ? "" : "there")).trim();
  const safeSubject = oneLine(subject, "Account email subject", 180);
  const safeTitle = oneLine(title, "Account email title", 180);
  const safeMessage = oneLine(message, "Account email message", 600);
  const safeUrl = oneLine(actionUrl, "Account action URL", 2048);
  const expiry = new Date(expiresAt);
  if (!Number.isFinite(expiry.getTime())) throw problem("Account action expiration is invalid", "invalid_email_message", 400);
  const text = [
    de ? `Hallo${name ? ` ${name}` : ""},` : `Hello ${name},`,
    "",
    safeTitle,
    safeMessage,
    "",
    `${actionLabel}: ${safeUrl}`,
    de
      ? `Dieser Link läuft am ${emailDate(expiry, lang)} ab und kann einmal verwendet werden.`
      : `This link expires at ${emailDate(expiry, lang)} and can be used once.`,
    "",
    ignoreMessage,
  ].join("\n");
  const html = `<!doctype html>
<html lang="${lang}"><body style="margin:0;background:#f4f6fb;color:#1d2740;font-family:Arial,sans-serif">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 14px;background:#f4f6fb">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;overflow:hidden;border:1px solid #e0e4ef;border-radius:18px;background:#ffffff">
        <tr><td style="padding:24px 28px;background:#11182a;color:#ffffff;font-size:20px;font-weight:700">nimbus <span style="color:#7580ff">direct</span></td></tr>
        <tr><td style="padding:34px 28px">
          <div style="display:inline-block;padding:7px 11px;border-radius:999px;background:#eef0ff;color:#5662dc;font-size:12px;font-weight:700">${escapeHtml(badge)}</div>
          <h1 style="margin:18px 0 10px;font-size:26px;line-height:1.25">${escapeHtml(safeTitle)}</h1>
          <p style="margin:0 0 22px;color:#667087;font-size:15px;line-height:1.65">${de ? `Hallo${name ? ` ${escapeHtml(name)}` : ""},` : `Hello ${escapeHtml(name)},`} ${escapeHtml(safeMessage)}</p>
          <table role="presentation" cellspacing="0" cellpadding="0"><tr><td style="border-radius:10px;background:#5b67e8"><a href="${escapeHtml(safeUrl)}" style="padding:13px 20px;display:inline-block;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700">${escapeHtml(actionLabel)}</a></td></tr></table>
          <p style="margin:20px 0 0;color:#8a93a8;font-size:12px;line-height:1.55">${de ? "Dieser private Link läuft am" : "This private link expires at"} ${escapeHtml(emailDate(expiry, lang))} ${de ? "ab und kann einmal verwendet werden." : "and can be used once."}</p>
          <div style="margin-top:22px;padding:14px 16px;border-radius:12px;background:#f7f8fb;color:#717b90;font-size:12px;line-height:1.55">${escapeHtml(ignoreMessage)}</div>
        </td></tr>
        <tr><td style="padding:18px 28px;border-top:1px solid #edf0f5;color:#929aad;font-size:11px">${de ? "Automatische Kontonachricht von Nimbus Direct" : "Automatic account message from Nimbus Direct"}</td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
  return { subject: safeSubject, text, html };
}

export function invitationEmailTemplate({ displayName, customerName, actionUrl, expiresAt, language = "en" }) {
  const de = normalizeEmailLanguage(language) === "de";
  return accountActionEmailTemplate({
    displayName,
    subject: de ? "Sie wurden zu Nimbus Direct eingeladen" : "You are invited to Nimbus Direct",
    badge: de ? "Kontoeinladung" : "Account invitation",
    title: de ? "Ihr Infrastrukturkonto ist bereit." : "Your infrastructure account is ready.",
    message: customerName
      ? (de
        ? `Ein Nimbus-Direct-Konto für ${customerName} wurde für Sie erstellt. Legen Sie Ihr persönliches Passwort fest, um fortzufahren.`
        : `A Nimbus Direct account for ${customerName} has been created for you. Choose your private password to continue.`)
      : (de
        ? "Ein Nimbus-Direct-Konto wurde für Sie erstellt. Legen Sie Ihr persönliches Passwort fest, um fortzufahren."
        : "A Nimbus Direct account has been created for you. Choose your private password to continue."),
    actionLabel: de ? "Mein Passwort festlegen" : "Create my password",
    actionUrl,
    expiresAt,
    ignoreMessage: de
      ? "Wenn Sie diese Einladung nicht erwartet haben, können Sie diese E-Mail bedenkenlos ignorieren."
      : "If you were not expecting this invitation, you can safely ignore this email.",
    language,
  });
}

export function passwordResetEmailTemplate({ displayName, actionUrl, expiresAt, language = "en" }) {
  const de = normalizeEmailLanguage(language) === "de";
  return accountActionEmailTemplate({
    displayName,
    subject: de ? "Setzen Sie Ihr Nimbus-Direct-Passwort zurück" : "Reset your Nimbus Direct password",
    badge: de ? "Passwortwiederherstellung" : "Password recovery",
    title: de ? "Setzen Sie Ihr Passwort zurück." : "Reset your password.",
    message: de
      ? "Für Ihr Nimbus-Direct-Konto wurde das Zurücksetzen des Passworts angefordert."
      : "A password reset was requested for your Nimbus Direct account.",
    actionLabel: de ? "Mein Passwort zurücksetzen" : "Reset my password",
    actionUrl,
    expiresAt,
    ignoreMessage: de
      ? "Wenn Sie dieses Zurücksetzen nicht angefordert haben, ist keine Aktion erforderlich und Ihr aktuelles Passwort bleibt gültig."
      : "If you did not request this reset, no action is required and your current password remains valid.",
    language,
  });
}

export function buildMimeMessage(settings, message) {
  const recipient = normalizeMailbox(message.to, "Recipient");
  const subject = oneLine(message.subject, "Subject", 240);
  const messageId = `<${randomBytes(18).toString("hex")}@${String(settings.host).replace(/[^A-Za-z0-9.-]/g, "") || "nimbus-direct"}>`;
  const headers = [
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${messageId}`,
    `From: ${displayMailbox(settings.fromName, settings.fromEmail)}`,
    `To: <${recipient}>`,
    `Subject: ${encodeHeader(subject)}`,
    "MIME-Version: 1.0",
    "Auto-Submitted: auto-generated",
    "X-Auto-Response-Suppress: All",
  ];
  if (settings.replyTo) headers.push(`Reply-To: <${normalizeMailbox(settings.replyTo, "Reply-to address")}>`);
  const text = String(message.text || "");
  const html = String(message.html || "");
  if (html) {
    const boundary = `nimbus_${randomBytes(16).toString("hex")}`;
    headers.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
    return `${headers.join("\r\n")}\r\n\r\n`
      + `--${boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${base64Lines(text)}\r\n`
      + `--${boundary}\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${base64Lines(html)}\r\n`
      + `--${boundary}--\r\n`;
  }
  headers.push("Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: base64");
  return `${headers.join("\r\n")}\r\n\r\n${base64Lines(text)}\r\n`;
}

function smtpFailure(error) {
  if (error?.code?.startsWith("smtp_")) return error;
  const code = {
    ENOTFOUND: "smtp_dns_failed",
    EAI_AGAIN: "smtp_dns_failed",
    ECONNREFUSED: "smtp_connection_failed",
    ECONNRESET: "smtp_connection_failed",
    EHOSTUNREACH: "smtp_connection_failed",
    ENETUNREACH: "smtp_connection_failed",
    ETIMEDOUT: "smtp_timeout",
    CERT_HAS_EXPIRED: "smtp_tls_failed",
    DEPTH_ZERO_SELF_SIGNED_CERT: "smtp_tls_failed",
    SELF_SIGNED_CERT_IN_CHAIN: "smtp_tls_failed",
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: "smtp_tls_failed",
    ERR_TLS_CERT_ALTNAME_INVALID: "smtp_tls_failed",
  }[error?.code] || "smtp_connection_failed";
  const messages = {
    smtp_dns_failed: "The SMTP hostname could not be resolved.",
    smtp_connection_failed: "Nimbus could not connect to the SMTP server.",
    smtp_timeout: "The SMTP server did not respond before the timeout.",
    smtp_tls_failed: "The SMTP server certificate could not be verified.",
  };
  return problem(messages[code], code);
}

class ReplyReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = "";
    this.waiters = [];
    this.closedError = null;
    this.onData = (chunk) => this.push(chunk);
    this.onError = (error) => this.close(smtpFailure(error));
    this.onEnd = () => this.close(problem("The SMTP server closed the connection.", "smtp_connection_closed"));
    socket.on("data", this.onData);
    socket.once("error", this.onError);
    socket.once("end", this.onEnd);
  }

  detach() {
    this.socket.off("data", this.onData);
    this.socket.off("error", this.onError);
    this.socket.off("end", this.onEnd);
  }

  close(error) {
    this.closedError = error;
    while (this.waiters.length) this.waiters.shift().reject(error);
  }

  push(chunk) {
    this.buffer += chunk.toString("utf8");
    this.flush();
  }

  flush() {
    while (this.waiters.length) {
      const parsed = this.parse();
      if (!parsed) return;
      this.waiters.shift().resolve(parsed);
    }
  }

  parse() {
    const lines = this.buffer.split("\r\n");
    if (lines.length < 2) return null;
    const collected = [];
    let consumed = 0;
    let responseCode = null;
    for (const line of lines.slice(0, -1)) {
      consumed += line.length + 2;
      const match = line.match(/^(\d{3})([ -])(.*)$/);
      if (!match) continue;
      responseCode ||= Number(match[1]);
      collected.push(match[3]);
      if (match[2] === " ") {
        this.buffer = this.buffer.slice(consumed);
        return { code: responseCode, lines: collected, message: collected.join(" ") };
      }
    }
    return null;
  }

  read() {
    const parsed = this.parse();
    if (parsed) return Promise.resolve(parsed);
    if (this.closedError) return Promise.reject(this.closedError);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }
}

function expect(reply, accepted, errorCode = "smtp_protocol_failed") {
  if (accepted.includes(reply.code)) return reply;
  const code = reply.code === 535 || reply.code === 534
    ? "smtp_auth_failed"
    : reply.code >= 400 && reply.code < 500
      ? "smtp_temporary_failure"
    : reply.code >= 500 && reply.code < 600
      ? errorCode
      : "smtp_protocol_failed";
  const messages = {
    smtp_auth_failed: "The SMTP server rejected the configured credentials.",
    smtp_recipient_rejected: "The SMTP server rejected the recipient address.",
    smtp_sender_rejected: "The SMTP server rejected the configured sender address.",
    smtp_starttls_unavailable: "The SMTP server does not offer STARTTLS.",
    smtp_temporary_failure: "The SMTP server is temporarily unavailable.",
    smtp_protocol_failed: "The SMTP server returned an unexpected response.",
    smtp_delivery_failed: "The SMTP server rejected the message.",
  };
  throw problem(messages[code] || messages.smtp_protocol_failed, code);
}

async function openSocket(settings, timeoutMs) {
  const options = {
    host: settings.host,
    port: Number(settings.port),
  };
  if (settings.security === "tls") {
    if (!isIP(settings.host)) options.servername = settings.host;
    options.rejectUnauthorized = true;
  }
  const socket = settings.security === "tls" ? connectTls(options) : connectNet(options);
  socket.setTimeout(timeoutMs, () => socket.destroy(Object.assign(new Error("SMTP timeout"), { code: "ETIMEDOUT" })));
  try {
    await new Promise((resolve, reject) => {
      const readyEvent = settings.security === "tls" ? "secureConnect" : "connect";
      socket.once(readyEvent, resolve);
      socket.once("error", reject);
    });
  } catch (error) {
    socket.destroy();
    throw smtpFailure(error);
  }
  return socket;
}

async function command(socket, reader, value, accepted, errorCode) {
  socket.write(`${value}\r\n`);
  return expect(await reader.read(), accepted, errorCode);
}

async function authenticate(socket, reader, settings, capabilities) {
  if (!settings.username) return;
  const methods = capabilities.filter((line) => /^AUTH(?:\s|=)/i.test(line)).join(" ").toUpperCase();
  if (methods.includes("PLAIN")) {
    const value = Buffer.from(`\0${settings.username}\0${settings.password || ""}`, "utf8").toString("base64");
    socket.write(`AUTH PLAIN ${value}\r\n`);
    const reply = await reader.read();
    if (reply.code === 334) await command(socket, reader, value, [235]);
    else expect(reply, [235]);
    return;
  }
  if (methods.includes("LOGIN")) {
    await command(socket, reader, "AUTH LOGIN", [334]);
    await command(socket, reader, Buffer.from(settings.username, "utf8").toString("base64"), [334]);
    await command(socket, reader, Buffer.from(settings.password || "", "utf8").toString("base64"), [235]);
    return;
  }
  throw problem("The SMTP server does not offer AUTH PLAIN or AUTH LOGIN.", "smtp_auth_unsupported");
}

async function createSession(settings, timeoutMs) {
  let socket = await openSocket(settings, timeoutMs);
  let reader = new ReplyReader(socket);
  try {
    expect(await reader.read(), [220]);
    let hello = await command(socket, reader, "EHLO nimbus-direct", [250]);
    if (settings.security === "starttls") {
      if (!hello.lines.some((line) => /^STARTTLS\b/i.test(line))) {
        throw problem("The SMTP server does not offer STARTTLS.", "smtp_starttls_unavailable");
      }
      await command(socket, reader, "STARTTLS", [220], "smtp_starttls_unavailable");
      reader.detach();
      const tlsOptions = { socket, rejectUnauthorized: true };
      if (!isIP(settings.host)) tlsOptions.servername = settings.host;
      const upgraded = connectTls(tlsOptions);
      await new Promise((resolve, reject) => {
        upgraded.once("secureConnect", resolve);
        upgraded.once("error", reject);
      }).catch((error) => { throw smtpFailure(error); });
      socket = upgraded;
      socket.setTimeout(timeoutMs, () => socket.destroy(Object.assign(new Error("SMTP timeout"), { code: "ETIMEDOUT" })));
      reader = new ReplyReader(socket);
      hello = await command(socket, reader, "EHLO nimbus-direct", [250]);
    }
    await authenticate(socket, reader, settings, hello.lines);
    return { socket, reader };
  } catch (error) {
    reader.detach();
    socket.destroy();
    throw smtpFailure(error);
  }
}

async function closeSession(session) {
  try { await command(session.socket, session.reader, "QUIT", [221]); }
  catch { /* The operation already succeeded; a failed QUIT is not actionable. */ }
  session.reader.detach();
  session.socket.end();
}

export function createSmtpTransport({ timeoutMs = 10_000 } = {}) {
  return {
    async verify(settings) {
      const session = await createSession(settings, timeoutMs);
      await closeSession(session);
      return { ok: true };
    },

    async send(settings, message) {
      const session = await createSession(settings, timeoutMs);
      try {
        await command(session.socket, session.reader, `MAIL FROM:<${normalizeMailbox(settings.fromEmail, "Sender address")}>`, [250], "smtp_sender_rejected");
        await command(session.socket, session.reader, `RCPT TO:<${normalizeMailbox(message.to, "Recipient")}>`, [250, 251], "smtp_recipient_rejected");
        await command(session.socket, session.reader, "DATA", [354], "smtp_delivery_failed");
        const mime = buildMimeMessage(settings, message)
          .replace(/(^|\r\n)\./g, "$1..")
          .replace(/\r\n$/, "");
        session.socket.write(`${mime}\r\n.\r\n`);
        const delivered = expect(await session.reader.read(), [250], "smtp_delivery_failed");
        const providerMessageId = delivered.message.match(/<[^<>@\s]+@[^<>\s]+>/)?.[0] || null;
        await closeSession(session);
        return { providerMessageId };
      } catch (error) {
        session.reader.detach();
        session.socket.destroy();
        throw smtpFailure(error);
      }
    },
  };
}

export function createEmailService({
  store,
  log = () => {},
  transport = createSmtpTransport(),
  queueIntervalMs = 5_000,
} = {}) {
  let timer = null;
  let processing = false;

  function connection({ allowDisabled = false } = {}) {
    const settings = store.getEmailConnection();
    if (!settings) throw problem("Configure SMTP delivery before testing email.", "email_not_configured", 409);
    if (!allowDisabled && !settings.enabled) throw problem("Email delivery is disabled.", "email_disabled", 409);
    return settings;
  }

  async function testConnection() {
    const settings = connection({ allowDisabled: true });
    try {
      await transport.verify(settings);
      store.setEmailTestResult({ status: "success" });
      return { ok: true, testedAt: Date.now() };
    } catch (error) {
      const safe = smtpFailure(error);
      store.setEmailTestResult({ status: "failed", errorCode: safe.code });
      throw safe;
    }
  }

  async function deliverClaimed(job, { allowDisabled = false } = {}) {
    try {
      const settings = connection({ allowDisabled });
      const payload = store.getEmailJobPayload(job.id);
      if (!payload) throw problem("The queued email payload is unavailable.", "email_payload_unavailable", 409);
      const result = await transport.send(settings, { to: job.to_email, subject: job.subject, ...payload });
      return store.completeEmailJob(job.id, { providerMessageId: result?.providerMessageId || null });
    } catch (error) {
      const safe = smtpFailure(error);
      const retryable = ![
        "email_not_configured", "email_disabled", "email_payload_unavailable", "invalid_email_address",
        "smtp_auth_failed", "smtp_auth_unsupported", "smtp_recipient_rejected", "smtp_sender_rejected",
      ].includes(safe.code);
      const updated = store.failEmailJob(job.id, { errorCode: safe.code, retryable });
      log("error", "email_delivery_failed", { jobId: job.id, error: safe.code, willRetry: updated.status === "pending" });
      throw Object.assign(safe, { job: updated });
    }
  }

  async function processJob(id, options = {}) {
    const job = store.claimEmailJob(id);
    if (!job) return store.getEmailJob(id);
    return deliverClaimed(job, options);
  }

  async function processDue() {
    if (processing) return;
    processing = true;
    try {
      if (!store.getEmailSettings().enabled) return;
      for (let index = 0; index < 10; index += 1) {
        const job = store.claimEmailJob();
        if (!job) break;
        try { await deliverClaimed(job); }
        catch { /* Failure state and retry time were persisted above. */ }
      }
    } finally {
      processing = false;
    }
  }

  async function sendTest(recipient, createdBy) {
    const settings = connection({ allowDisabled: true });
    const to = normalizeMailbox(recipient, "Test recipient");
    const content = testEmailTemplate(settings, to, store.getUser(createdBy)?.preferredLanguage);
    const job = store.queueEmail({
      to,
      ...content,
      category: "delivery_test",
      createdBy,
      maxAttempts: 1,
    });
    return processJob(job.id, { allowDisabled: true });
  }

  function start() {
    store.recoverEmailJobs();
    if (timer) return;
    timer = setInterval(() => void processDue(), queueIntervalMs);
    timer.unref();
    void processDue();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  return {
    testConnection,
    sendTest,
    processDue,
    processJob,
    start,
    stop,
  };
}
