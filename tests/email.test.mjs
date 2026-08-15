import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildMimeMessage,
  createEmailService,
  invitationEmailTemplate,
  maintenanceEmailTemplate,
  normalizeMailbox,
  passwordResetEmailTemplate,
  securityEmailTemplate,
  supportTicketEmailTemplate,
} from "../server/email.mjs";
import { openStore } from "../server/store.mjs";

const APP_SECRET = "email-test-secret-that-is-long-and-unique";

async function temporaryStore(callback) {
  const directory = await mkdtemp(join(tmpdir(), "nimbus-direct-email-"));
  const store = await openStore(directory, { appSecret: APP_SECRET });
  try { return await callback(store); }
  finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
}

test("email service verifies SMTP and delivers a queued test without exposing content", async () => {
  await temporaryStore(async (store) => {
    const admin = await store.createUser({
      email: "admin@example.test",
      displayName: "Admin",
      password: "admin password for email tests",
      role: "admin",
    });
    store.saveEmailSettings({
      enabled: true,
      host: "smtp.example.test",
      port: 587,
      security: "starttls",
      username: "nimbus@example.test",
      password: "smtp-password-secret",
      fromName: "Nimbus Direct",
      fromEmail: "nimbus@example.test",
      replyTo: "support@example.test",
      appUrl: "https://panel.example.test/",
    }, { userId: admin.id });
    assert.equal(store.getEmailSettings().appUrl, "https://panel.example.test");
    assert.throws(() => store.saveEmailSettings({ appUrl: "http://panel.example.test" }), (error) => error.code === "invalid_app_url");

    const calls = [];
    const transport = {
      async verify(settings) {
        calls.push(["verify", settings.host, settings.password]);
        return { ok: true };
      },
      async send(settings, message) {
        calls.push(["send", settings.host, message.to, message.subject, message.text, message.html]);
        return { providerMessageId: "<provider-id@example.test>" };
      },
    };
    const service = createEmailService({ store, transport, queueIntervalMs: 60_000 });
    assert.equal((await service.testConnection()).ok, true);
    assert.equal(store.getEmailSettings().lastTestStatus, "success");

    const delivered = await service.sendTest("recipient@example.test", admin.id);
    assert.equal(delivered.status, "sent");
    assert.equal(delivered.providerMessageId, "<provider-id@example.test>");
    assert.equal(store.getEmailJobPayload(delivered.id), null);
    assert.equal(calls[0][0], "verify");
    assert.deepEqual(calls[1].slice(0, 4), [
      "send", "smtp.example.test", "recipient@example.test", "Nimbus Direct email delivery test",
    ]);
    assert.match(calls[1][4], /email delivery is working/i);
    assert.match(calls[1][5], /Delivery verified/);
  });
});

test("email service records sanitized failures and failed test jobs", async () => {
  await temporaryStore(async (store) => {
    const admin = await store.createUser({
      email: "admin@example.test",
      displayName: "Admin",
      password: "admin password for email tests",
      role: "admin",
    });
    store.saveEmailSettings({
      enabled: false,
      host: "smtp.example.test",
      port: 465,
      security: "tls",
      username: "nimbus@example.test",
      password: "wrong-secret",
      fromName: "Nimbus Direct",
      fromEmail: "nimbus@example.test",
    }, { userId: admin.id });
    const failure = Object.assign(new Error("provider said the password was wrong and included sensitive detail"), {
      code: "smtp_auth_failed",
      status: 502,
    });
    const service = createEmailService({
      store,
      transport: {
        async verify() { throw failure; },
        async send() { throw failure; },
      },
    });

    await assert.rejects(() => service.testConnection(), (error) => error.code === "smtp_auth_failed");
    assert.equal(store.getEmailSettings().lastTestErrorCode, "smtp_auth_failed");
    await assert.rejects(() => service.sendTest("recipient@example.test", admin.id), (error) =>
      error.code === "smtp_auth_failed" && error.job.status === "failed");
    const job = store.listEmailJobs().items[0];
    assert.equal(job.lastErrorCode, "smtp_auth_failed");
    assert.equal(JSON.stringify(job).includes("provider said"), false);
  });
});

test("MIME generation validates headers and creates text/html alternatives", () => {
  const settings = {
    host: "smtp.example.test",
    fromName: "Nimbus Direct",
    fromEmail: "nimbus@example.test",
    replyTo: "support@example.test",
  };
  const mime = buildMimeMessage(settings, {
    to: "customer@example.test",
    subject: "Server notification",
    text: "Plain text",
    html: "<strong>HTML</strong>",
  });
  assert.match(mime, /Content-Type: multipart\/alternative/);
  assert.match(mime, /Reply-To: <support@example\.test>/);
  assert.equal(mime.includes("<strong>HTML</strong>"), false);
  assert.equal(normalizeMailbox(" Customer@Example.Test "), "customer@example.test");
  assert.throws(() => normalizeMailbox("bad\r\nBcc: victim@example.test"), (error) => error.code === "invalid_email_address");
});

test("security notices use the branded template without trusting user content", () => {
  const content = securityEmailTemplate({
    displayName: "<Operator>",
    title: "Two-factor authentication enabled",
    message: "Authenticator protection is active.",
    ipAddress: "192.0.2.44",
    occurredAt: new Date("2026-07-25T12:00:00.000Z"),
    timeZone: "Europe/Berlin",
  });
  assert.equal(content.subject, "Nimbus Direct: Two-factor authentication enabled");
  assert.match(content.text, /192\.0\.2\.44/);
  assert.match(content.html, /Account security/);
  assert.equal(content.html.includes("<Operator>"), false);
  assert.match(content.html, /&lt;Operator&gt;/);
  assert.match(content.text, /07\/25\/2026, 02:00 PM GMT\+2/);
  assert.equal(content.text.includes("2026-07-25T12:00:00.000Z"), false);
});

test("maintenance emails escape customer-facing content and describe the service window", () => {
  const content = maintenanceEmailTemplate({
    displayName: "<Customer>",
    event: {
      kind: "maintenance",
      status: "scheduled",
      severity: "warning",
      title: "Network maintenance <Berlin>",
      message: "A brief interruption is possible.\nNo action is required.",
      startsAt: Date.parse("2026-07-26T22:00:00.000Z"),
      endsAt: Date.parse("2026-07-26T23:00:00.000Z"),
      timeZone: "Europe/Berlin",
      lockGroups: [{ id: "power_management", label: "Power management" }],
    },
    appUrl: "https://panel.example.test/#maintenance",
  });
  assert.equal(content.subject, "Scheduled: Network maintenance <Berlin>");
  assert.match(content.text, /07\/27\/2026, 12:00 AM GMT\+2/);
  assert.equal(content.text.includes("2026-07-26T22:00:00.000Z"), false);
  assert.match(content.text, /View maintenance status/);
  assert.match(content.text, /Power management/);
  assert.match(content.html, /Planned maintenance · Scheduled/);
  assert.match(content.html, /Network maintenance &lt;Berlin&gt;/);
  assert.equal(content.html.includes("<Customer>"), false);
  assert.match(content.html, /A brief interruption is possible\.<br>No action is required\./);
  assert.match(content.html, /Temporary action lock/);
});

test("support emails escape conversation content and link to the private ticket", () => {
  const content = supportTicketEmailTemplate({
    displayName: "<Customer>",
    ticket: {
      reference: "ND-20260726-ABC123",
      subject: "Network issue <VM>",
      status: "waiting_customer",
    },
    message: "The route was repaired.\nPlease test again <now>.",
    actorName: "<Support Admin>",
    eventType: "reply",
    appUrl: "https://panel.example.test/#support/private-ticket-id",
  });
  assert.equal(content.subject, "[ND-20260726-ABC123] New reply: Network issue <VM>");
  assert.match(content.text, /Open this support ticket/);
  assert.match(content.html, /Open support ticket/);
  assert.match(content.html, /Network issue &lt;VM&gt;/);
  assert.match(content.html, /Please test again &lt;now&gt;\./);
  assert.equal(content.html.includes("<Customer>"), false);
  assert.equal(content.html.includes("<Support Admin>"), false);

  const status = supportTicketEmailTemplate({
    displayName: "Customer",
    ticket: {
      reference: "ND-20260726-ABC123",
      subject: "Network issue",
      status: "resolved",
    },
    message: "The ticket status changed to resolved.",
    actorName: "Support Admin",
    eventType: "status",
  });
  assert.match(status.subject, /Ticket updated/);
  assert.match(status.html, /support ticket was updated/i);
});

test("account-action emails contain only escaped, expiring single-use links", () => {
  const invitation = invitationEmailTemplate({
    displayName: "<Invited User>",
    customerName: "Acme & Sons",
    actionUrl: "https://panel.example.test/?invite=private-token",
    expiresAt: Date.parse("2026-07-25T18:30:00.000Z"),
  });
  assert.equal(invitation.subject, "You are invited to Nimbus Direct");
  assert.match(invitation.text, /invite=private-token/);
  assert.match(invitation.text, /used once/);
  assert.match(invitation.html, /Create my password/);
  assert.match(invitation.html, /&lt;Invited User&gt;/);
  assert.match(invitation.text, /A Nimbus Direct account for Acme & Sons has been created for you/);
  assert.match(invitation.html, /A Nimbus Direct account for Acme &amp; Sons has been created for you/);
  assert.equal(invitation.html.includes("<Invited User>"), false);
  assert.equal(invitation.text.toLowerCase().includes("temporary password"), false);

  const recovery = passwordResetEmailTemplate({
    displayName: "Secured User",
    actionUrl: "https://panel.example.test/?reset=private-token",
    expiresAt: Date.parse("2026-07-25T18:30:00.000Z"),
  });
  assert.equal(recovery.subject, "Reset your Nimbus Direct password");
  assert.match(recovery.text, /reset=private-token/);
  assert.match(recovery.html, /Reset my password/);
  assert.match(recovery.text, /current password remains valid/i);
});

test("account, security, maintenance, support, and alert templates support German", () => {
  const invitation = invitationEmailTemplate({
    displayName: "Liam",
    customerName: "Beispiel GmbH",
    actionUrl: "https://panel.example.test/?invite=secret",
    expiresAt: Date.parse("2026-08-03T18:30:00.000Z"),
    language: "de",
  });
  assert.equal(invitation.subject, "Sie wurden zu Nimbus Direct eingeladen");
  assert.match(invitation.text, /persönliches Passwort/);
  assert.match(invitation.html, /lang="de"/);

  const security = securityEmailTemplate({
    displayName: "Liam",
    title: "Two-factor authentication enabled",
    message: "Authenticator protection is active for your account.",
    language: "de",
  });
  assert.equal(security.subject, "Nimbus Direct: Zwei-Faktor-Authentifizierung aktiviert");
  assert.match(security.html, /Kontosicherheit/);

  const maintenance = maintenanceEmailTemplate({
    displayName: "Liam",
    language: "de",
    event: {
      kind: "maintenance",
      status: "scheduled",
      severity: "warning",
      title: "Netzwerkwartung",
      message: "Kurze Unterbrechung möglich.",
      startsAt: Date.parse("2026-08-04T17:00:00.000Z"),
      endsAt: Date.parse("2026-08-04T17:30:00.000Z"),
      timeZone: "Europe/Berlin",
      lockGroups: [],
    },
  });
  assert.equal(maintenance.subject, "Geplant: Netzwerkwartung");
  assert.match(maintenance.text, /Geplante Wartung/);
  assert.match(maintenance.text, /Beginn: 04\.08\.2026, 19:00 MESZ/);
  assert.match(maintenance.text, /Ende: 04\.08\.2026, 19:30 MESZ/);
  assert.match(maintenance.html, /Geplante Wartung · Geplant/);

  const support = supportTicketEmailTemplate({
    displayName: "Liam",
    ticket: { reference: "ND-1", subject: "Hilfe", status: "waiting_customer" },
    message: "Bitte erneut testen.",
    actorName: "Support",
    language: "de",
  });
  assert.equal(support.subject, "[ND-1] Neue Antwort: Hilfe");
  assert.match(support.text, /Wartet auf Kunden/);
});
