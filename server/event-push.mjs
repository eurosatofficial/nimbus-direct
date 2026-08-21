import { defaultLanguage, normalizeLanguage, translate } from "./locales.mjs";

function copy(language, source, replacements = {}) {
  return translate(normalizeLanguage(language) || defaultLanguage, source, replacements);
}

function preferredLanguage(recipient) {
  return recipient?.preferredLanguage || recipient?.preferred_language || defaultLanguage;
}

function singleLine(value, fallback = "Nimbus Direct") {
  return String(value || fallback).replace(/\s+/g, " ").trim();
}

function preview(value, maximum = 220) {
  const clean = singleLine(value, "");
  return clean.length > maximum ? `${clean.slice(0, maximum - 1).trimEnd()}…` : clean;
}

function localizedSecurityCopy(value, language) {
  const source = String(value || "");
  const apiKey = source.match(/^The API key “(.+)” was created for your Nimbus Direct account\. Revoke it immediately if you did not create it\.$/);
  if (apiKey) return copy(language, "The API key “{name}” was created for your Nimbus Direct account. Revoke it immediately if you did not create it.", { name: apiKey[1] });
  const revokedApiKey = source.match(/^The API key “(.+)” was revoked and can no longer access your Nimbus Direct account\.$/);
  if (revokedApiKey) return copy(language, "The API key “{name}” was revoked and can no longer access your Nimbus Direct account.", { name: revokedApiKey[1] });
  const adminRevokedApiKey = source.match(/^An administrator revoked the API key “(.+)” for your Nimbus Direct account\.$/);
  if (adminRevokedApiKey) return copy(language, "An administrator revoked the API key “{name}” for your Nimbus Direct account.", { name: adminRevokedApiKey[1] });
  const passkeyAdded = source.match(/^The passkey “(.+)” can now sign in to your Nimbus Direct account without a password\.$/);
  if (passkeyAdded) return copy(language, "The passkey “{name}” can now sign in to your Nimbus Direct account without a password.", { name: passkeyAdded[1] });
  const passkeyRemoved = source.match(/^The passkey “(.+)” can no longer sign in to your Nimbus Direct account\.$/);
  if (passkeyRemoved) return copy(language, "The passkey “{name}” can no longer sign in to your Nimbus Direct account.", { name: passkeyRemoved[1] });
  return copy(language, source);
}

export function maintenancePushContent(event, language = defaultLanguage, phase = null) {
  const status = phase || event?.status || "scheduled";
  const titleSource = {
    scheduled: "Maintenance scheduled: {title}",
    active: "Maintenance in progress: {title}",
    resolved: "Maintenance resolved: {title}",
    cancelled: "Maintenance cancelled: {title}",
  }[status] || "Maintenance update: {title}";
  const messageSource = {
    resolved: "The maintenance event has been marked as resolved.",
    cancelled: "The scheduled maintenance event was cancelled.",
  }[status];
  return {
    title: copy(language, titleSource, { title: singleLine(event?.title, copy(language, "Maintenance")) }),
    message: preview(messageSource ? copy(language, messageSource) : event?.message),
    type: `maintenance.${status}`,
  };
}

export function supportPushContent({ ticket, actor, eventType = "reply" }, language = defaultLanguage) {
  const actorName = singleLine(actor?.displayName || actor?.display_name, copy(language, "Nimbus Direct support"));
  const subject = singleLine(ticket?.subject, copy(language, "Support ticket"));
  const reference = singleLine(ticket?.reference, "");
  const status = copy(language, String(ticket?.status || "open").replaceAll("_", " "));
  if (eventType === "created") {
    return {
      title: copy(language, "New support ticket: {subject}", { subject }),
      message: copy(language, "{actor} created ticket {reference}.", { actor: actorName, reference }),
      type: "support.ticket.created",
    };
  }
  if (eventType === "status") {
    return {
      title: copy(language, "Support ticket updated: {subject}", { subject }),
      message: copy(language, "Ticket {reference} is now {status}.", { reference, status }),
      type: "support.ticket.status",
    };
  }
  return {
    title: copy(language, "New support reply: {subject}", { subject }),
    message: copy(language, "{actor} replied to ticket {reference}.", { actor: actorName, reference }),
    type: "support.ticket.reply",
  };
}

export function securityPushContent({ title, message }, language = defaultLanguage) {
  return {
    title: localizedSecurityCopy(title, language),
    message: preview(localizedSecurityCopy(message, language)),
    type: "security.notice",
  };
}

export function operationsPushContent(incident, language = defaultLanguage, resolved = false) {
  return {
    title: copy(language, resolved ? "Operations recovered: {title}" : "Operations alert: {title}", {
      title: singleLine(incident?.title, copy(language, "Infrastructure incident")),
    }),
    message: copy(language, resolved
      ? "This infrastructure incident has been resolved."
      : "Open the Operations Center for details."),
    type: resolved ? "operations.incident.resolved" : "operations.incident.firing",
  };
}

export function createEventPushService({ store, push, log = () => {} } = {}) {
  function deliver(recipient, content, identifiers = {}) {
    if (!push?.configured || !recipient?.id) return false;
    void push.sendUser(recipient.id, {
      ...content,
      notificationId: identifiers.notificationId || null,
      resourceId: identifiers.resourceId || null,
      collapseId: identifiers.collapseId || null,
    }).catch((error) => {
      log("error", "event_push_delivery_failed", {
        userId: recipient.id,
        type: content.type,
        error: error.code || error.message,
      });
    });
    return true;
  }

  function maintenance({ event, deliveries = [] }, { phase = null } = {}) {
    const status = phase || event?.status || "scheduled";
    const resolution = ["resolved", "cancelled"].includes(status);
    let queued = 0;
    for (const recipient of deliveries) {
      const eligible = recipient.inAppEnabled !== false
        && (resolution ? recipient.resolutionAlerts : recipient.infrastructureAlerts) !== false;
      if (!eligible) continue;
      if (deliver(recipient, maintenancePushContent(event, preferredLanguage(recipient), status), {
        notificationId: recipient.deliveryId || null,
        collapseId: `maintenance:${event.id}`,
      })) queued += 1;
    }
    return queued;
  }

  function support({ ticket, actor, audience, eventType = "reply" }) {
    if (!ticket) return 0;
    let queued = 0;
    for (const recipient of store.listSupportTicketRecipients(ticket.id, audience)) {
      if (recipient.id === actor?.id || recipient.inAppEnabled === false) continue;
      if (deliver(recipient, supportPushContent({ ticket, actor, eventType }, preferredLanguage(recipient)), {
        notificationId: ticket.id,
        resourceId: ticket.resourceId || null,
        collapseId: `support:${ticket.id}`,
      })) queued += 1;
    }
    return queued;
  }

  function security(user, notice) {
    if (!user?.id) return 0;
    return deliver(user, securityPushContent(notice, preferredLanguage(user)), {
      collapseId: `security:${user.id}`,
    }) ? 1 : 0;
  }

  function operations({ opened = [], resolved = [] } = {}) {
    if (!push?.configured || (!opened.length && !resolved.length)) return 0;
    const recipients = store.listActiveAdministrators();
    let queued = 0;
    for (const recipient of recipients) {
      if (recipient.inAppEnabled === false) continue;
      for (const incident of opened) {
        if (deliver(recipient, operationsPushContent(incident, preferredLanguage(recipient), false), {
          collapseId: `operations:${incident.id}`,
        })) queued += 1;
      }
      for (const incident of resolved) {
        if (deliver(recipient, operationsPushContent(incident, preferredLanguage(recipient), true), {
          collapseId: `operations:${incident.id}`,
        })) queued += 1;
      }
    }
    return queued;
  }

  return { maintenance, support, security, operations };
}
