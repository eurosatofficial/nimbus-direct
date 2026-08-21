import test from "node:test";
import assert from "node:assert/strict";
import {
  createEventPushService,
  maintenancePushContent,
  operationsPushContent,
  securityPushContent,
  supportPushContent,
} from "../server/event-push.mjs";

test("event push copy is localized for maintenance, support, and security", () => {
  assert.equal(maintenancePushContent({ title: "Netzwerk", message: "Kurze Unterbrechung" }, "de", "scheduled").title, "Wartung geplant: Netzwerk");
  assert.equal(maintenancePushContent({ title: "Netzwerk" }, "de", "resolved").message, "Die Wartung wurde als beendet markiert.");
  assert.deepEqual(supportPushContent({
    ticket: { subject: "Server down", reference: "ND-123", status: "waiting_support" },
    actor: { displayName: "Liam" },
    eventType: "reply",
  }, "de"), {
    title: "Neue Support-Antwort: Server down",
    message: "Liam hat auf Ticket ND-123 geantwortet.",
    type: "support.ticket.reply",
  });
  assert.equal(securityPushContent({
    title: "A passkey was added",
    message: "The passkey “iPhone” can now sign in to your Nimbus Direct account without a password.",
  }, "de").message, "Der Passkey „iPhone“ kann sich jetzt ohne Passwort bei Ihrem Nimbus-Direct-Konto anmelden.");
  assert.equal(securityPushContent({
    title: "An API key was revoked",
    message: "The API key “Home Assistant” was revoked and can no longer access your Nimbus Direct account.",
  }, "de").message, "Der API-Schlüssel „Home Assistant“ wurde widerrufen und kann nicht mehr auf Ihr Nimbus-Direct-Konto zugreifen.");
  assert.equal(operationsPushContent({ title: "pve1 is unreachable" }, "de", true).title, "Betrieb wiederhergestellt: pve1 is unreachable");
});

test("event push service respects recipient scope, preferences, and actor exclusion", async () => {
  const sent = [];
  const service = createEventPushService({
    store: {
      listSupportTicketRecipients: () => [
        { id: "actor", displayName: "Actor", preferredLanguage: "en", inAppEnabled: true },
        { id: "de-user", displayName: "Kunde", preferredLanguage: "de", inAppEnabled: true },
        { id: "muted", displayName: "Muted", preferredLanguage: "en", inAppEnabled: false },
      ],
      listActiveAdministrators: () => [
        { id: "admin", preferredLanguage: "de", inAppEnabled: true },
        { id: "muted-admin", preferredLanguage: "en", inAppEnabled: false },
      ],
    },
    push: {
      configured: true,
      async sendUser(userId, notification) { sent.push({ userId, notification }); },
    },
  });

  assert.equal(service.support({
    ticket: { id: "ticket-1", subject: "VM", reference: "ND-1", status: "open", resourceId: "cluster:qemu:101" },
    actor: { id: "actor", displayName: "Administrator" },
    audience: "customer",
    eventType: "reply",
  }), 1);
  assert.equal(service.maintenance({
    event: { id: "maintenance-1", title: "Storage", message: "Storage migration", status: "scheduled" },
    deliveries: [
      { id: "de-user", deliveryId: "delivery-1", preferredLanguage: "de", inAppEnabled: true, infrastructureAlerts: true, resolutionAlerts: true },
      { id: "muted", deliveryId: "delivery-2", preferredLanguage: "en", inAppEnabled: false, infrastructureAlerts: true, resolutionAlerts: true },
      { id: "no-alerts", deliveryId: "delivery-3", preferredLanguage: "en", inAppEnabled: true, infrastructureAlerts: false, resolutionAlerts: false },
    ],
  }), 1);
  assert.equal(service.security({ id: "de-user", preferred_language: "de" }, {
    title: "Your password was changed",
    message: "Your Nimbus Direct password was changed and every active session was signed out.",
  }), 1);
  assert.equal(service.operations({
    opened: [{ id: "incident-1", title: "pve1 is unreachable" }],
    resolved: [{ id: "incident-2", title: "Storage recovered" }],
  }), 2);

  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(sent.length, 5);
  assert.equal(sent[0].userId, "de-user");
  assert.equal(sent[0].notification.type, "support.ticket.reply");
  assert.equal(sent[0].notification.resourceId, "cluster:qemu:101");
  assert.equal(sent[1].notification.type, "maintenance.scheduled");
  assert.equal(sent[1].notification.notificationId, "delivery-1");
  assert.equal(sent[2].notification.type, "security.notice");
  assert.equal(sent[3].notification.type, "operations.incident.firing");
  assert.equal(sent[4].notification.type, "operations.incident.resolved");
  assert.equal(sent.some((entry) => ["actor", "muted", "no-alerts", "muted-admin"].includes(entry.userId)), false);
});
