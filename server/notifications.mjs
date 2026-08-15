import { defaultLanguage, localeFor, normalizeLanguage, translate } from "./locales.mjs";

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  })[character]);
}

function resourceLabel(resource) {
  return resource?.displayName || resource?.resourceName || resource?.name || (resource ? `${resource.type.toUpperCase()} ${resource.vmid}` : "Server");
}

function notificationCopy(language, source, replacements = {}) {
  return translate(normalizeLanguage(language) || defaultLanguage, source, replacements);
}

function actionLabel(action, language = defaultLanguage) {
  const source = ({
    start: "Start",
    stop: "Stop",
    shutdown: "Shutdown",
    reboot: "Reboot operation",
    reset: "Reset",
    suspend: "Suspend",
    resume: "Resume",
    snapshot_create: "Snapshot creation",
    snapshot_restore: "Snapshot restoration",
    snapshot_delete: "Snapshot deletion",
  })[action] || String(action || "Action").replaceAll("_", " ");
  return notificationCopy(language, source);
}

export function localizedNotificationEvent(event, resource, language = defaultLanguage) {
  const lang = normalizeLanguage(language) || defaultLanguage;
  const label = resourceLabel(resource);
  if (event.type?.startsWith("action.")) {
    const action = event.type.slice("action.".length);
    const actionName = actionLabel(action, lang);
    const success = event.category === "action_success";
    return {
      ...event,
      title: notificationCopy(lang, success ? "{action} completed" : "{action} failed", { action: actionName }),
      message: success
        ? notificationCopy(lang, "{action} completed successfully on {resource}.", { action: actionName, resource: label })
        : notificationCopy(lang, "Proxmox reported that {action} failed on {resource}.", { action: actionName, resource: label }),
    };
  }
  const typeMatch = event.type?.match(/^alert\.(offline|cpu|memory|storage)\.(firing|resolved)$/);
  if (!typeMatch) return event;
  const [, metric, state] = typeMatch;
  const values = [...String(event.message || "").matchAll(/(\d+)%?/g)].map((match) => Number(match[1]));
  if (metric === "offline") {
    const minutes = values[0] || resource?.alertPolicy?.sustainMinutes || 1;
    return state === "firing"
      ? {
        ...event,
        title: notificationCopy(lang, "{resource} is offline", { resource: label }),
        message: notificationCopy(lang, minutes === 1
          ? "{resource} has remained stopped for {count} minute."
          : "{resource} has remained stopped for {count} minutes.", { resource: label, count: minutes }),
      }
      : {
        ...event,
        title: notificationCopy(lang, "{resource} is online again", { resource: label }),
        message: notificationCopy(lang, "{resource} is running again.", { resource: label }),
      };
  }
  const noun = notificationCopy(lang, { cpu: "CPU", memory: "Memory", storage: "Storage" }[metric]);
  const threshold = values[0] ?? resource?.alertPolicy?.[`${metric}Threshold`] ?? 0;
  const current = values.at(-1) ?? 0;
  const minutes = values.length > 2 ? values[1] : (resource?.alertPolicy?.sustainMinutes || 1);
  return state === "firing"
    ? {
      ...event,
      title: notificationCopy(lang, metric === "storage" ? "Storage is filling up on {resource}" : "High {metric} usage on {resource}", { metric: noun, resource: label }),
      message: notificationCopy(lang, minutes === 1
        ? "{metric} usage has remained at or above {threshold}% for {count} minute. Current usage is {current}%."
        : "{metric} usage has remained at or above {threshold}% for {count} minutes. Current usage is {current}%.",
      { metric: noun, threshold, count: minutes, current }),
    }
    : {
      ...event,
      title: notificationCopy(lang, "{metric} usage recovered on {resource}", { metric: noun, resource: label }),
      message: notificationCopy(lang, "{metric} usage is back below {threshold}%. Current usage is {current}%.", { metric: noun, threshold, current }),
    };
}

export function localizeNotificationPage(page, language) {
  return { ...page, items: page.items.map((event) => localizedNotificationEvent(event, event, language)) };
}

function categoryEnabled(preferences, category) {
  return {
    action_success: preferences.actionSuccess,
    action_failure: preferences.actionFailure,
    infrastructure_alert: preferences.infrastructureAlerts,
    resolution: preferences.resolutionAlerts,
  }[category] !== false;
}

export function notificationEmailTemplate(event, resource, language = "en", timeZone = "UTC") {
  const lang = normalizeLanguage(language) || defaultLanguage;
  event = localizedNotificationEvent(event, resource, lang);
  const sentAt = new Date();
  const label = resourceLabel(resource);
  const badge = {
    critical: { text: notificationCopy(lang, "Action required"), background: "#fff0f0", color: "#c23b3b" },
    warning: { text: notificationCopy(lang, "Infrastructure alert"), background: "#fff6e7", color: "#b66a12" },
    success: { text: notificationCopy(lang, "Resolved"), background: "#eaf8f2", color: "#16865f" },
    info: { text: notificationCopy(lang, "Nimbus update"), background: "#eef0ff", color: "#5564dc" },
  }[event.severity] || { text: notificationCopy(lang, "Nimbus update"), background: "#eef0ff", color: "#5564dc" };
  const details = resource ? `
            <tr><td style="color:#8a93a8;font-size:12px">Server</td><td align="right" style="font-size:13px;font-weight:700">${escapeHtml(label)}</td></tr>
            <tr><td style="color:#8a93a8;font-size:12px">${escapeHtml(notificationCopy(lang, "Resource"))}</td><td align="right" style="font-size:13px;font-weight:700">${escapeHtml(resource.type?.toUpperCase())} ${Number(resource.vmid)} · ${escapeHtml(resource.node)}</td></tr>` : "";
  const sentDate = new Intl.DateTimeFormat(localeFor(lang), {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    timeZone, timeZoneName: "short",
  }).format(sentAt);
  const text = [
    event.title,
    "",
    event.message,
    ...(resource ? ["", `Server: ${label}`, `${notificationCopy(lang, "Resource")}: ${resource.type.toUpperCase()} ${resource.vmid}`, `${notificationCopy(lang, "Node")}: ${resource.node}`] : []),
    "",
    notificationCopy(lang, "Sent by Nimbus Direct at {date}", { date: sentDate }),
  ].join("\n");
  const html = `<!doctype html>
<html lang="${lang}"><body style="margin:0;background:#f4f6fb;color:#1d2740;font-family:Arial,sans-serif">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 14px;background:#f4f6fb">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;overflow:hidden;border:1px solid #e0e4ef;border-radius:18px;background:#ffffff">
        <tr><td style="padding:24px 28px;background:#11182a;color:#ffffff;font-size:20px;font-weight:700">nimbus <span style="color:#7580ff">direct</span></td></tr>
        <tr><td style="padding:34px 28px">
          <div style="display:inline-block;padding:7px 11px;border-radius:999px;background:${badge.background};color:${badge.color};font-size:12px;font-weight:700">${badge.text}</div>
          <h1 style="margin:18px 0 10px;font-size:26px;line-height:1.25">${escapeHtml(event.title)}</h1>
          <p style="margin:0 0 22px;color:#667087;font-size:15px;line-height:1.65">${escapeHtml(event.message)}</p>
          ${resource ? `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:separate;border-spacing:0 8px">${details}</table>` : ""}
        </td></tr>
        <tr><td style="padding:18px 28px;border-top:1px solid #edf0f5;color:#929aad;font-size:11px">${escapeHtml(notificationCopy(lang, "Sent by Nimbus Direct at {date}", { date: sentDate }))}</td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
  return { subject: event.title, text, html };
}

export function createNotificationService({
  store,
  email,
  push = null,
  log = () => {},
  now = () => Date.now(),
} = {}) {
  async function emitEvent(input) {
    const created = store.createNotificationEvent(input);
    if (!created.created) return { event: created.event, created: false, deliveries: 0 };
    const resource = input.resourceId ? store.getResource(input.resourceId) : null;
    const emailAvailable = store.getEmailSettings().enabled;
    let deliveries = 0;
    for (const user of store.listActiveCustomerUsers(input.customerId)) {
      const preferences = store.getNotificationPreferences(user.id);
      if (!categoryEnabled(preferences, input.category)) continue;
      const sendInApp = preferences.inAppEnabled;
      const sendEmail = preferences.emailEnabled && emailAvailable;
      if (!sendInApp && !sendEmail) continue;
      const delivery = store.createNotificationDelivery({
        eventId: created.event.eventId,
        userId: user.id,
        inAppVisible: sendInApp,
      });
      if (!delivery.created) continue;
      deliveries += 1;
      if (sendEmail) {
        try {
          const content = notificationEmailTemplate(created.event, resource, user.preferredLanguage, user.preferredTimeZone);
          const job = store.queueEmail({
            to: user.email,
            ...content,
            category: "notification",
            maxAttempts: 4,
          });
          store.setNotificationEmailJob(delivery.id, job.id);
          void email.processDue();
        } catch (error) {
          log("error", "notification_email_queue_failed", {
            eventId: created.event.eventId,
            userId: user.id,
            error: error.code || error.message,
          });
        }
      }
      if (sendInApp && push?.configured) {
        const localized = localizedNotificationEvent(created.event, resource, user.preferredLanguage);
        void push.sendUser(user.id, {
          title: localized.title,
          message: localized.message,
          type: created.event.type,
          resourceId: created.event.resourceId,
          notificationId: delivery.id,
          collapseId: created.event.eventId,
        });
      }
    }
    return { event: created.event, created: true, deliveries };
  }

  async function actionCompleted(task) {
    const resource = store.getResource(task.resource_id || task.resourceId);
    const customerId = task.customer_id || task.customerId || resource?.customerId;
    if (!resource || !customerId) return null;
    const success = (task.exit_status ?? task.exitStatus) === "OK";
    const action = task.action;
    const label = actionLabel(action);
    return emitEvent({
      customerId,
      resourceId: resource.id,
      category: success ? "action_success" : "action_failure",
      type: `action.${action}`,
      severity: success ? "info" : "critical",
      title: success ? `${label} completed` : `${label} failed`,
      message: success
        ? `${label} completed successfully on ${resourceLabel(resource)}.`
        : `Proxmox reported that ${label.toLowerCase()} failed on ${resourceLabel(resource)}.`,
      dedupKey: `task:${task.id}:completed`,
    });
  }

  function alertDefinitions(resource) {
    const policy = resource.alertPolicy;
    const running = resource.status === "running";
    const memoryPercent = resource.memory > 0 ? Math.round(resource.memoryUsed / resource.memory * 100) : 0;
    const storageUsageAvailable = resource.storageUsageAvailable !== false;
    const storagePercent = storageUsageAvailable && resource.storage > 0
      ? Math.round(resource.storageUsed / resource.storage * 100)
      : 0;
    return [
      {
        type: "offline",
        enabled: policy.offline,
        condition: resource.status === "stopped",
        value: resource.status === "stopped" ? 1 : 0,
        threshold: null,
        firingTitle: `${resourceLabel(resource)} is offline`,
        firingMessage: `${resourceLabel(resource)} has remained stopped for ${policy.sustainMinutes} minute${policy.sustainMinutes === 1 ? "" : "s"}.`,
        recoveryTitle: `${resourceLabel(resource)} is online again`,
        recoveryMessage: `${resourceLabel(resource)} is running again.`,
      },
      {
        type: "cpu",
        enabled: policy.cpu,
        condition: running && resource.cpu >= policy.cpuThreshold,
        value: resource.cpu,
        threshold: policy.cpuThreshold,
        firingTitle: `High CPU usage on ${resourceLabel(resource)}`,
        firingMessage: `CPU usage has remained at or above ${policy.cpuThreshold}% for ${policy.sustainMinutes} minute${policy.sustainMinutes === 1 ? "" : "s"}. Current usage is ${Math.round(resource.cpu)}%.`,
        recoveryTitle: `CPU usage recovered on ${resourceLabel(resource)}`,
        recoveryMessage: `CPU usage is back below ${policy.cpuThreshold}%. Current usage is ${Math.round(resource.cpu)}%.`,
      },
      {
        type: "memory",
        enabled: policy.memory,
        condition: running && resource.memory > 0 && memoryPercent >= policy.memoryThreshold,
        value: memoryPercent,
        threshold: policy.memoryThreshold,
        firingTitle: `High memory usage on ${resourceLabel(resource)}`,
        firingMessage: `Memory usage has remained at or above ${policy.memoryThreshold}% for ${policy.sustainMinutes} minute${policy.sustainMinutes === 1 ? "" : "s"}. Current usage is ${memoryPercent}%.`,
        recoveryTitle: `Memory usage recovered on ${resourceLabel(resource)}`,
        recoveryMessage: `Memory usage is back below ${policy.memoryThreshold}%. Current usage is ${memoryPercent}%.`,
      },
      {
        type: "storage",
        enabled: policy.storage,
        observable: storageUsageAvailable,
        condition: storageUsageAvailable && resource.storage > 0 && storagePercent >= policy.storageThreshold,
        value: storagePercent,
        threshold: policy.storageThreshold,
        firingTitle: `Storage is filling up on ${resourceLabel(resource)}`,
        firingMessage: `Storage usage has remained at or above ${policy.storageThreshold}% for ${policy.sustainMinutes} minute${policy.sustainMinutes === 1 ? "" : "s"}. Current usage is ${storagePercent}%.`,
        recoveryTitle: `Storage usage recovered on ${resourceLabel(resource)}`,
        recoveryMessage: `Storage usage is back below ${policy.storageThreshold}%. Current usage is ${storagePercent}%.`,
      },
    ];
  }

  async function evaluateDefinition(resource, definition) {
    const timestamp = now();
    const existing = store.getAlertState(resource.assignmentId, definition.type);
    if (!definition.enabled) {
      if (existing) store.upsertAlertState(resource.assignmentId, definition.type, {
        status: "healthy",
        conditionActive: false,
        firstObservedAt: null,
        lastValue: definition.value,
      });
      return { fired: false, resolved: false };
    }
    if (definition.observable === false) {
      return { fired: false, resolved: false };
    }

    if (!existing) {
      if (definition.type === "offline") {
        store.upsertAlertState(resource.assignmentId, definition.type, {
          status: "healthy",
          conditionActive: definition.condition,
          firstObservedAt: null,
          lastValue: definition.value,
        });
        return { fired: false, resolved: false };
      }
      store.upsertAlertState(resource.assignmentId, definition.type, {
        status: definition.condition ? "pending" : "healthy",
        conditionActive: definition.condition,
        firstObservedAt: definition.condition ? timestamp : null,
        lastValue: definition.value,
      });
      return { fired: false, resolved: false };
    }

    if (!definition.condition) {
      if (existing.status === "firing") {
        await emitEvent({
          customerId: resource.customerId,
          resourceId: resource.id,
          category: "resolution",
          type: `alert.${definition.type}.resolved`,
          severity: "success",
          title: definition.recoveryTitle,
          message: definition.recoveryMessage,
          dedupKey: `alert:${resource.assignmentId}:${definition.type}:${existing.first_observed_at}:resolved`,
        });
        store.upsertAlertState(resource.assignmentId, definition.type, {
          status: "healthy",
          conditionActive: false,
          firstObservedAt: null,
          lastValue: definition.value,
        });
        return { fired: false, resolved: true };
      }
      store.upsertAlertState(resource.assignmentId, definition.type, {
        status: "healthy",
        conditionActive: false,
        firstObservedAt: null,
        lastValue: definition.value,
      });
      return { fired: false, resolved: false };
    }

    if (!existing.condition_active) {
      if (definition.type === "offline" && store.hasRecentTaskRequest(resource.id, ["stop", "shutdown"], { since: timestamp - 15 * 60_000 })) {
        store.upsertAlertState(resource.assignmentId, definition.type, {
          status: "healthy",
          conditionActive: true,
          firstObservedAt: null,
          lastValue: definition.value,
        });
        return { fired: false, resolved: false };
      }
      store.upsertAlertState(resource.assignmentId, definition.type, {
        status: "pending",
        conditionActive: true,
        firstObservedAt: timestamp,
        lastValue: definition.value,
      });
      return { fired: false, resolved: false };
    }

    if (existing.status === "healthy") {
      store.upsertAlertState(resource.assignmentId, definition.type, {
        status: "healthy",
        conditionActive: true,
        firstObservedAt: null,
        lastValue: definition.value,
      });
      return { fired: false, resolved: false };
    }
    if (existing.status === "firing") {
      store.upsertAlertState(resource.assignmentId, definition.type, {
        status: "firing",
        conditionActive: true,
        lastValue: definition.value,
      });
      return { fired: false, resolved: false };
    }

    const sustained = timestamp - Number(existing.first_observed_at || timestamp) >= resource.alertPolicy.sustainMinutes * 60_000;
    const cooledDown = !existing.last_notified_at
      || timestamp - Number(existing.last_notified_at) >= resource.alertPolicy.cooldownMinutes * 60_000;
    if (!sustained || !cooledDown) {
      store.upsertAlertState(resource.assignmentId, definition.type, {
        status: "pending",
        conditionActive: true,
        lastValue: definition.value,
      });
      return { fired: false, resolved: false };
    }

    await emitEvent({
      customerId: resource.customerId,
      resourceId: resource.id,
      category: "infrastructure_alert",
      type: `alert.${definition.type}.firing`,
      severity: definition.type === "offline" ? "critical" : "warning",
      title: definition.firingTitle,
      message: definition.firingMessage,
      dedupKey: `alert:${resource.assignmentId}:${definition.type}:${existing.first_observed_at}:firing`,
    });
    store.upsertAlertState(resource.assignmentId, definition.type, {
      status: "firing",
      conditionActive: true,
      firstObservedAt: existing.first_observed_at,
      lastValue: definition.value,
      lastNotifiedAt: timestamp,
    });
    return { fired: true, resolved: false };
  }

  async function evaluateResourceAlerts({ clusterId = null } = {}) {
    const summary = { checked: 0, fired: 0, resolved: 0 };
    for (const resource of store.listAlertAssignments({ clusterId })) {
      for (const definition of alertDefinitions(resource)) {
        const result = await evaluateDefinition(resource, definition);
        summary.checked += 1;
        if (result.fired) summary.fired += 1;
        if (result.resolved) summary.resolved += 1;
      }
    }
    return summary;
  }

  return { emitEvent, actionCompleted, evaluateResourceAlerts };
}
