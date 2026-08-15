const json = (schema) => ({
  "application/json": { schema },
});

const response = (description, schema = null) => ({
  description,
  ...(schema ? { content: json(schema) } : {}),
});

const operation = ({
  tags,
  summary,
  description,
  public: isPublic = false,
  body,
  parameters,
  success = 200,
  responseSchema = { type: "object", additionalProperties: true },
}) => ({
  tags: [tags],
  summary,
  ...(description ? { description } : {}),
  ...(isPublic ? { security: [] } : {}),
  ...(parameters ? { parameters } : {}),
  ...(body ? {
    requestBody: {
      required: true,
      content: json(body),
    },
  } : {}),
  responses: {
    [success]: response(success === 204 ? "Completed with no response body." : "Successful response.", success === 204 ? null : responseSchema),
    "400": { $ref: "#/components/responses/BadRequest" },
    "401": { $ref: "#/components/responses/Unauthorized" },
    "403": { $ref: "#/components/responses/Forbidden" },
    "404": { $ref: "#/components/responses/NotFound" },
    "409": { $ref: "#/components/responses/Conflict" },
    "429": { $ref: "#/components/responses/RateLimited" },
  },
});

const resourceId = {
  name: "resourceId",
  in: "path",
  required: true,
  description: "Nimbus resource identifier. The server derives cluster, node, type, and VMID from this value.",
  schema: { type: "string" },
};
const ticketId = { name: "ticketId", in: "path", required: true, schema: { type: "string" } };
const taskId = { name: "taskId", in: "path", required: true, schema: { type: "string" } };
const deliveryId = { name: "deliveryId", in: "path", required: true, schema: { type: "string" } };
const sessionId = { name: "sessionId", in: "path", required: true, schema: { type: "string" } };
const snapshotName = { name: "snapshotName", in: "path", required: true, schema: { type: "string" } };
const imageId = { name: "imageId", in: "path", required: true, schema: { type: "string" } };
const keyId = { name: "keyId", in: "path", required: true, schema: { type: "string" } };
const passkeyId = { name: "passkeyId", in: "path", required: true, schema: { type: "string" } };
const adminId = (name) => ({ name, in: "path", required: true, schema: { type: "string" } });

const tokenRequest = {
  type: "object",
  required: ["email", "password"],
  properties: {
    email: { type: "string", format: "email" },
    password: { type: "string", format: "password" },
    deviceName: { type: "string", minLength: 1, maxLength: 100 },
    platform: { type: "string", enum: ["ios", "android", "desktop", "other"] },
    appVersion: { type: "string", maxLength: 60 },
  },
};
const mfaRequest = {
  type: "object",
  required: ["challengeToken", "code"],
  properties: {
    challengeToken: { type: "string" },
    code: { type: "string" },
    deviceName: { type: "string", minLength: 1, maxLength: 100 },
    platform: { type: "string", enum: ["ios", "android", "desktop", "other"] },
    appVersion: { type: "string", maxLength: 60 },
  },
};

export const nimbusOpenApi = {
  openapi: "3.1.0",
  info: {
    title: "Nimbus Direct API",
    version: "1.2.0",
    description: [
      "The versioned application API for Nimbus Direct web and mobile clients.",
      "Every resource operation is checked against Nimbus's local assignment and permission database before the official Proxmox API is called.",
      "Native clients use short-lived bearer access tokens and single-use rotating refresh tokens. Browser cookie sessions remain supported by the same business routes.",
      "User-managed nmb_key_ integration keys use the same Bearer header, but are additionally restricted by administrator policy groups, the key's selected groups and resources, and live assignment permissions.",
    ].join("\n\n"),
  },
  servers: [{ url: "/api/v1", description: "Current Nimbus Direct installation" }],
  tags: [
    { name: "System", description: "API discovery and contract." },
    { name: "Authentication", description: "Native device login, 2FA, refresh rotation, and device sessions." },
    { name: "Account", description: "Current-user profile and account security." },
    { name: "API keys", description: "User-managed, administrator-limited integration credentials." },
    { name: "Resources", description: "Assignment-scoped QEMU and LXC inventory and operations." },
    { name: "Tasks", description: "Customer-safe Proxmox task status." },
    { name: "Snapshots", description: "Permission-scoped snapshot inventory and actions." },
    { name: "Media", description: "Customer-owned QEMU ISO media." },
    { name: "Notifications", description: "Private notifications and preferences." },
    { name: "Maintenance", description: "Targeted maintenance and incident notices." },
    { name: "Support", description: "Tenant-scoped support conversations." },
    { name: "Administration", description: "Administrator-only Nimbus control-center operations." },
  ],
  security: [{ bearerAuth: [] }],
  paths: {
    "/": {
      get: operation({
        tags: "System",
        summary: "Discover API version and capabilities",
        description: "Public discovery includes privacy.operatorPolicyUrl when this self-hosted server's operator configured a privacy policy. A null value means clients must hide the operator-specific link; it is not a fallback for the separate iOS app privacy policy.",
        public: true,
      }),
    },
    "/openapi.json": {
      get: operation({
        tags: "System",
        summary: "Download the OpenAPI contract",
        public: true,
      }),
    },
    "/auth/token": {
      post: operation({
        tags: "Authentication",
        summary: "Create a native device session",
        description: "Returns tokens directly, or HTTP 202 with an MFA challenge when 2FA is enabled.",
        public: true,
        body: tokenRequest,
        responseSchema: {
          oneOf: [
            { $ref: "#/components/schemas/TokenResponse" },
            { $ref: "#/components/schemas/MfaChallenge" },
          ],
        },
      }),
    },
    "/auth/mfa": {
      post: operation({
        tags: "Authentication",
        summary: "Complete a native 2FA login",
        public: true,
        body: mfaRequest,
        responseSchema: { $ref: "#/components/schemas/TokenResponse" },
      }),
    },
    "/auth/refresh": {
      post: operation({
        tags: "Authentication",
        summary: "Rotate a refresh token",
        description: "The submitted refresh token becomes unusable. Reuse revokes the entire device session.",
        public: true,
        body: {
          type: "object",
          required: ["refreshToken"],
          properties: { refreshToken: { type: "string" } },
        },
        responseSchema: { $ref: "#/components/schemas/TokenResponse" },
      }),
    },
    "/auth/logout": {
      post: operation({ tags: "Authentication", summary: "Revoke the current device session", success: 204 }),
    },
    "/auth/session": {
      get: operation({ tags: "Authentication", summary: "Inspect the current native session" }),
    },
    "/auth/devices": {
      get: operation({ tags: "Authentication", summary: "List the current user's native device sessions" }),
    },
    "/auth/devices/{sessionId}": {
      delete: operation({
        tags: "Authentication",
        summary: "Revoke one native device session",
        parameters: [sessionId],
        success: 204,
      }),
    },
    "/me": {
      get: operation({ tags: "Account", summary: "Get the current user, security state, and client capabilities" }),
    },
    "/dashboard": {
      get: operation({ tags: "Account", summary: "Get the complete role-aware dashboard payload" }),
    },
    "/profile": {
      patch: operation({
        tags: "Account",
        summary: "Update the current user's profile, email language, and timezone",
        body: {
          type: "object",
          minProperties: 1,
          properties: {
            displayName: { type: "string" },
            preferredLanguage: { type: "string", description: "Language code installed in public/locales/languages.json" },
            preferredTimeZone: { type: "string", description: "IANA timezone used for account email timestamps" },
          },
        },
      }),
    },
    "/password": {
      post: operation({
        tags: "Account",
        summary: "Change password and revoke every session",
        body: {
          type: "object",
          required: ["currentPassword", "password"],
          properties: {
            currentPassword: { type: "string", format: "password" },
            password: { type: "string", format: "password" },
          },
        },
        success: 204,
      }),
    },
    "/security/passkeys/registration/options": {
      post: operation({
        tags: "Account",
        summary: "Start passkey registration",
        description: "Requires the current account password and returns a short-lived, single-use WebAuthn challenge bound to this account.",
        body: {
          type: "object",
          required: ["currentPassword"],
          properties: { currentPassword: { type: "string", format: "password" } },
        },
      }),
    },
    "/security/passkeys/registration/verify": {
      post: operation({
        tags: "Account",
        summary: "Finish passkey registration",
        description: "Verifies the relying-party origin, RP ID, challenge, and user verification before storing the public credential.",
        success: 201,
        body: {
          type: "object",
          required: ["challengeToken", "response", "name"],
          properties: {
            challengeToken: { type: "string" },
            response: { type: "object", additionalProperties: true },
            name: { type: "string", minLength: 1, maxLength: 100 },
          },
        },
      }),
    },
    "/security/passkeys/{passkeyId}": {
      patch: operation({
        tags: "Account",
        summary: "Rename one owned passkey",
        parameters: [passkeyId],
        body: {
          type: "object",
          required: ["name"],
          properties: { name: { type: "string", minLength: 1, maxLength: 100 } },
        },
      }),
      delete: operation({
        tags: "Account",
        summary: "Remove one owned passkey",
        description: "Requires the current account password.",
        parameters: [passkeyId],
        body: {
          type: "object",
          required: ["currentPassword"],
          properties: { currentPassword: { type: "string", format: "password" } },
        },
      }),
    },
    "/api-keys": {
      get: operation({
        tags: "API keys",
        summary: "List the current user's API policy, available groups and resources, and existing keys",
        description: "Integration keys cannot call API-key management endpoints.",
      }),
      post: operation({
        tags: "API keys",
        summary: "Create an integration API key and return its secret once",
        description: "Requires the current account password and, when enabled, a valid authenticator or recovery code.",
        success: 201,
        body: {
          type: "object",
          required: ["name", "groups", "resourceIds", "currentPassword"],
          properties: {
            name: { type: "string", minLength: 1, maxLength: 100 },
            groups: { type: "array", items: { type: "string" }, minItems: 1, uniqueItems: true },
            resourceIds: { type: "array", items: { type: "string" }, uniqueItems: true },
            expiresAt: { type: ["integer", "null"] },
            currentPassword: { type: "string", format: "password" },
            code: { type: "string" },
          },
        },
      }),
    },
    "/api-keys/preview": {
      post: operation({
        tags: "API keys",
        summary: "Preview the effective permission summary before creating a key",
        body: {
          type: "object",
          required: ["name", "groups", "resourceIds"],
          properties: {
            name: { type: "string" },
            groups: { type: "array", items: { type: "string" } },
            resourceIds: { type: "array", items: { type: "string" } },
            expiresAt: { type: ["integer", "null"] },
          },
        },
      }),
    },
    "/api-keys/{keyId}": {
      get: operation({ tags: "API keys", summary: "Read one API key's live permission summary", parameters: [keyId] }),
      delete: operation({ tags: "API keys", summary: "Revoke one API key", parameters: [keyId], success: 204 }),
    },
    "/security/mfa/setup": {
      post: operation({
        tags: "Account",
        summary: "Start authenticator enrollment",
        body: {
          type: "object",
          required: ["currentPassword"],
          properties: { currentPassword: { type: "string", format: "password" } },
        },
      }),
    },
    "/security/mfa/confirm": {
      post: operation({
        tags: "Account",
        summary: "Confirm authenticator enrollment",
        body: {
          type: "object",
          required: ["code"],
          properties: { code: { type: "string" } },
        },
      }),
    },
    "/security/mfa/disable": {
      post: operation({
        tags: "Account",
        summary: "Disable authenticator protection",
        body: {
          type: "object",
          required: ["currentPassword", "code"],
          properties: {
            currentPassword: { type: "string", format: "password" },
            code: { type: "string" },
          },
        },
      }),
    },
    "/security/mfa/recovery-codes": {
      post: operation({
        tags: "Account",
        summary: "Replace all recovery codes",
        body: {
          type: "object",
          required: ["currentPassword", "code"],
          properties: {
            currentPassword: { type: "string", format: "password" },
            code: { type: "string" },
          },
        },
      }),
    },
    "/security/sessions/revoke-others": {
      post: operation({
        tags: "Account",
        summary: "Revoke every other browser and native session",
        body: {
          type: "object",
          required: ["currentPassword"],
          properties: { currentPassword: { type: "string", format: "password" } },
        },
      }),
    },
    "/security/sessions/{sessionId}": {
      delete: operation({
        tags: "Account",
        summary: "Revoke an active browser or native session",
        parameters: [sessionId],
        success: 204,
      }),
    },
    "/resources": {
      get: operation({
        tags: "Resources",
        summary: "List only resources visible to the current user",
        parameters: [
          { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 200 } },
          { name: "offset", in: "query", schema: { type: "integer", minimum: 0 } },
          { name: "type", in: "query", schema: { type: "string", enum: ["qemu", "lxc"] } },
          { name: "status", in: "query", schema: { type: "string" } },
          { name: "clusterId", in: "query", schema: { type: "string" } },
          { name: "search", in: "query", schema: { type: "string" } },
        ],
      }),
    },
    "/resources/refresh": {
      post: operation({
        tags: "Resources",
        summary: "Synchronize visible resource state from Proxmox",
        description: "Nimbus derives the eligible clusters from the authenticated user's role, assignments, API-key resource restrictions, and enabled cluster configuration. Clients cannot select arbitrary clusters, nodes, or VMIDs.",
      }),
    },
    "/resources/{resourceId}": {
      get: operation({
        tags: "Resources",
        summary: "Get assignment-scoped resource details",
        parameters: [resourceId],
      }),
    },
    "/resources/{resourceId}/network": {
      get: operation({
        tags: "Resources",
        summary: "Get current network information for one resource",
        parameters: [resourceId],
      }),
    },
    "/resources/{resourceId}/history": {
      get: operation({
        tags: "Resources",
        summary: "Get Proxmox RRD usage history",
        parameters: [
          resourceId,
          { name: "timeframe", in: "query", schema: { type: "string", enum: ["hour", "day", "week", "month", "year"] } },
        ],
      }),
    },
    "/resources/{resourceId}/actions": {
      post: operation({
        tags: "Resources",
        summary: "Request a permitted power action",
        description: "Nimbus resolves the Proxmox coordinates from the authorized local assignment. Clients cannot choose a node or VMID.",
        parameters: [resourceId, {
          name: "Idempotency-Key",
          in: "header",
          required: false,
          schema: { type: "string", maxLength: 120 },
        }],
        body: {
          type: "object",
          required: ["action"],
          properties: {
            action: { type: "string", enum: ["start", "stop", "shutdown", "reboot", "reset", "suspend", "resume"] },
          },
        },
      }),
    },
    "/resources/{resourceId}/console": {
      post: operation({
        tags: "Resources",
        summary: "Create a short-lived console launch session",
        parameters: [resourceId],
        success: 201,
      }),
    },
    "/console/session/{sessionId}": {
      get: operation({
        tags: "Resources",
        summary: "Resolve a short-lived console launch session",
        parameters: [sessionId],
      }),
    },
    "/console/native-launch/{sessionId}": {
      get: operation({
        tags: "Resources",
        summary: "Exchange a mobile console launch token for a console-only browser handoff",
        parameters: [sessionId],
      }),
    },
    "/push/devices": {
      post: operation({
        tags: "Notifications",
        summary: "Register an encrypted native APNs device token",
        body: {
          type: "object",
          required: ["token", "platform", "environment"],
          properties: {
            token: { type: "string" },
            platform: { type: "string", enum: ["ios"] },
            environment: { type: "string", enum: ["sandbox", "production"] },
            appVersion: { type: "string" },
          },
        },
      }),
    },
    "/push/devices/unregister": {
      post: operation({
        tags: "Notifications",
        summary: "Unregister the current iOS APNs device token",
        body: {
          type: "object",
          required: ["token"],
          properties: { token: { type: "string" } },
        },
        success: 204,
      }),
    },
    "/resources/{resourceId}/config": {
      put: operation({
        tags: "Resources",
        summary: "Change selected allowed configuration values",
        parameters: [resourceId],
        body: { type: "object", additionalProperties: true },
      }),
    },
    "/network": {
      get: operation({ tags: "Resources", summary: "Get network information for all visible resources" }),
    },
    "/resources/{resourceId}/snapshots": {
      get: operation({
        tags: "Snapshots",
        summary: "List snapshots and the assignment snapshot policy",
        parameters: [resourceId],
      }),
      post: operation({
        tags: "Snapshots",
        summary: "Create a snapshot",
        parameters: [resourceId],
        body: {
          type: "object",
          required: ["name"],
          properties: {
            name: { type: "string" },
            description: { type: "string", maxLength: 500 },
            includeMemory: { type: "boolean" },
          },
        },
      }),
    },
    "/resources/{resourceId}/snapshots/{snapshotName}/{operation}": {
      post: operation({
        tags: "Snapshots",
        summary: "Restore or delete a snapshot",
        parameters: [
          resourceId,
          snapshotName,
          { name: "operation", in: "path", required: true, schema: { type: "string", enum: ["restore", "delete"] } },
        ],
        body: {
          type: "object",
          required: ["confirmName"],
          properties: { confirmName: { type: "string" } },
        },
      }),
    },
    "/resources/{resourceId}/media": {
      get: operation({ tags: "Media", summary: "Get customer-owned ISO media and current mount state", parameters: [resourceId] }),
    },
    "/resources/{resourceId}/media/upload": {
      post: {
        tags: ["Media"],
        summary: "Upload an ISO directly to allowed Proxmox storage",
        description: "Streams application/octet-stream content without retaining a second ISO in Nimbus.",
        parameters: [
          resourceId,
          { name: "policyId", in: "query", required: true, schema: { type: "string" } },
          { name: "X-Nimbus-Filename", in: "header", required: true, schema: { type: "string", maxLength: 255 } },
          { name: "X-Nimbus-Size", in: "header", required: true, schema: { type: "integer", minimum: 1 } },
        ],
        requestBody: {
          required: true,
          content: {
            "application/octet-stream": {
              schema: { type: "string", format: "binary" },
            },
          },
        },
        responses: {
          "201": response("The ISO was streamed and is ready."),
          "202": response("Proxmox is still processing the uploaded ISO."),
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
          "429": { $ref: "#/components/responses/RateLimited" },
        },
      },
    },
    "/resources/{resourceId}/media/mount": {
      post: operation({
        tags: "Media",
        summary: "Mount a customer-owned ISO",
        parameters: [resourceId],
        body: {
          type: "object",
          required: ["isoImageId"],
          properties: { isoImageId: { type: "string" } },
        },
      }),
    },
    "/resources/{resourceId}/media/eject": {
      post: operation({ tags: "Media", summary: "Eject the Nimbus-managed ISO", parameters: [resourceId] }),
    },
    "/resources/{resourceId}/media/boot-once": {
      post: operation({ tags: "Media", summary: "Boot once from the verified mounted ISO", parameters: [resourceId] }),
    },
    "/resources/{resourceId}/media/boot-once/cancel": {
      post: operation({ tags: "Media", summary: "Cancel and restore a one-time ISO boot override", parameters: [resourceId] }),
    },
    "/resources/{resourceId}/media/{imageId}": {
      delete: operation({
        tags: "Media",
        summary: "Delete a customer-owned ISO",
        parameters: [resourceId, imageId],
        success: 204,
      }),
    },
    "/tasks": {
      get: operation({
        tags: "Tasks",
        summary: "List task status visible to the current user",
        parameters: [
          { name: "resourceId", in: "query", schema: { type: "string" } },
          { name: "limit", in: "query", schema: { type: "integer", minimum: 1 } },
        ],
      }),
    },
    "/tasks/{taskId}": {
      get: operation({ tags: "Tasks", summary: "Refresh and return one task", parameters: [taskId] }),
    },
    "/notifications": {
      get: operation({ tags: "Notifications", summary: "List private notifications and preferences" }),
    },
    "/notifications/preferences": {
      patch: operation({
        tags: "Notifications",
        summary: "Update notification preferences",
        body: { type: "object", additionalProperties: { type: "boolean" } },
      }),
    },
    "/notifications/read-all": {
      post: operation({ tags: "Notifications", summary: "Mark every notification as read" }),
    },
    "/notifications/{deliveryId}/read": {
      post: operation({
        tags: "Notifications",
        summary: "Mark one notification as read",
        parameters: [deliveryId],
        success: 204,
      }),
    },
    "/maintenance": {
      get: operation({ tags: "Maintenance", summary: "List targeted maintenance and incident notices" }),
    },
    "/maintenance/{deliveryId}/read": {
      post: operation({
        tags: "Maintenance",
        summary: "Mark one maintenance delivery as read",
        parameters: [deliveryId],
        success: 204,
      }),
    },
    "/support/tickets": {
      get: operation({ tags: "Support", summary: "List support tickets visible to the current user" }),
      post: operation({
        tags: "Support",
        summary: "Create a customer support ticket",
        body: {
          type: "object",
          required: ["subject", "message"],
          properties: {
            subject: { type: "string" },
            message: { type: "string" },
            category: { type: "string" },
            priority: { type: "string" },
            resourceId: { type: ["string", "null"] },
          },
        },
        success: 201,
      }),
    },
    "/support/tickets/{ticketId}": {
      get: operation({ tags: "Support", summary: "Get a tenant-scoped support conversation", parameters: [ticketId] }),
      patch: operation({
        tags: "Support",
        summary: "Update ticket administration fields",
        parameters: [ticketId],
        body: { type: "object", additionalProperties: true },
      }),
    },
    "/support/tickets/{ticketId}/messages": {
      post: operation({
        tags: "Support",
        summary: "Add a reply or administrator internal note",
        parameters: [ticketId],
        body: {
          type: "object",
          required: ["message"],
          properties: {
            message: { type: "string" },
            internal: { type: "boolean" },
          },
        },
        success: 201,
      }),
    },
    "/support/tickets/{ticketId}/{operation}": {
      post: operation({
        tags: "Support",
        summary: "Mark read, close, or reopen a ticket",
        parameters: [
          ticketId,
          { name: "operation", in: "path", required: true, schema: { type: "string", enum: ["read", "close", "reopen"] } },
        ],
      }),
    },
    "/admin/state": {
      get: operation({ tags: "Administration", summary: "Get the complete administrator control-center state" }),
    },
    "/admin/email/settings": {
      put: operation({
        tags: "Administration",
        summary: "Save encrypted SMTP delivery settings",
        body: { type: "object", additionalProperties: true },
      }),
    },
    "/admin/email/test-connection": {
      post: operation({
        tags: "Administration",
        summary: "Verify the configured SMTP connection",
        body: { type: "object", additionalProperties: true },
      }),
    },
    "/admin/email/test-message": {
      post: operation({
        tags: "Administration",
        summary: "Queue and deliver a branded test message",
        body: { type: "object", additionalProperties: true },
      }),
    },
    "/admin/email/jobs/{jobId}/retry": {
      post: operation({
        tags: "Administration",
        summary: "Retry a failed email job",
        parameters: [adminId("jobId")],
      }),
    },
    "/admin/security/policy": {
      patch: operation({
        tags: "Administration",
        summary: "Update central 2FA and login-alert policy",
        body: { type: "object", additionalProperties: { type: "boolean" } },
      }),
    },
    "/admin/operations": {
      get: operation({ tags: "Administration", summary: "Get Operations Center telemetry and incidents" }),
    },
    "/admin/operations/refresh": {
      post: operation({ tags: "Administration", summary: "Refresh Operations Center telemetry" }),
    },
    "/admin/operations/incidents/{incidentId}/acknowledge": {
      post: operation({
        tags: "Administration",
        summary: "Acknowledge an Operations Center incident",
        parameters: [adminId("incidentId")],
      }),
    },
    "/admin/maintenance-events": {
      post: operation({
        tags: "Administration",
        summary: "Create a maintenance or incident draft",
        body: { type: "object", additionalProperties: true },
        success: 201,
      }),
    },
    "/admin/maintenance-events/{eventId}": {
      patch: operation({
        tags: "Administration",
        summary: "Update a maintenance draft",
        parameters: [adminId("eventId")],
        body: { type: "object", additionalProperties: true },
      }),
      delete: operation({
        tags: "Administration",
        summary: "Delete a maintenance draft",
        parameters: [adminId("eventId")],
        success: 204,
      }),
    },
    "/admin/maintenance-events/{eventId}/{operation}": {
      post: operation({
        tags: "Administration",
        summary: "Publish, resolve, or cancel a maintenance event",
        parameters: [
          adminId("eventId"),
          { name: "operation", in: "path", required: true, schema: { type: "string", enum: ["publish", "resolve", "cancel"] } },
        ],
      }),
    },
    "/admin/customers": {
      post: operation({ tags: "Administration", summary: "Create a customer", body: { type: "object", additionalProperties: true }, success: 201 }),
    },
    "/admin/customers/{customerId}": {
      patch: operation({ tags: "Administration", summary: "Update a customer", parameters: [adminId("customerId")], body: { type: "object", additionalProperties: true } }),
      delete: operation({ tags: "Administration", summary: "Delete a customer", parameters: [adminId("customerId")], success: 204 }),
    },
    "/admin/users": {
      post: operation({ tags: "Administration", summary: "Create or invite a user", body: { type: "object", additionalProperties: true }, success: 201 }),
    },
    "/admin/invitations": {
      post: operation({
        tags: "Administration",
        summary: "Create a user and send a single-use invitation",
        body: { type: "object", additionalProperties: true },
        success: 201,
      }),
    },
    "/admin/users/{userId}": {
      patch: operation({ tags: "Administration", summary: "Update a user", parameters: [adminId("userId")], body: { type: "object", additionalProperties: true } }),
      delete: operation({ tags: "Administration", summary: "Delete a user", parameters: [adminId("userId")], success: 204 }),
    },
    "/admin/users/{userId}/password": {
      post: operation({
        tags: "Administration",
        summary: "Reset a user's password and revoke all sessions",
        parameters: [adminId("userId")],
        body: { type: "object", additionalProperties: true },
        success: 204,
      }),
    },
    "/admin/users/{userId}/mfa/reset": {
      post: operation({
        tags: "Administration",
        summary: "Reset a user's 2FA and revoke all sessions",
        parameters: [adminId("userId")],
        body: { type: "object", additionalProperties: true },
      }),
    },
    "/admin/users/{userId}/passkeys/reset": {
      post: operation({
        tags: "Administration",
        summary: "Remove every passkey from a user and revoke all sessions",
        parameters: [adminId("userId")],
        body: {
          type: "object",
          required: ["currentPassword"],
          properties: { currentPassword: { type: "string", format: "password" } },
        },
      }),
    },
    "/admin/users/{userId}/invitation/{operation}": {
      post: operation({
        tags: "Administration",
        summary: "Resend or revoke a pending invitation",
        parameters: [
          adminId("userId"),
          { name: "operation", in: "path", required: true, schema: { type: "string", enum: ["resend", "revoke"] } },
        ],
      }),
    },
    "/admin/users/{userId}/api-access": {
      get: operation({
        tags: "Administration",
        summary: "Read a user's integration API policy and keys",
        parameters: [adminId("userId")],
      }),
      patch: operation({
        tags: "Administration",
        summary: "Set the maximum API groups, resources, key count, and lifetime for a user",
        parameters: [adminId("userId")],
        body: { type: "object", additionalProperties: true },
      }),
    },
    "/admin/users/{userId}/api-keys/{keyId}": {
      delete: operation({
        tags: "Administration",
        summary: "Revoke one user's integration API key",
        parameters: [adminId("userId"), keyId],
        success: 204,
      }),
    },
    "/admin/users/{userId}/api-keys/revoke-all": {
      post: operation({
        tags: "Administration",
        summary: "Revoke every active integration API key for one user",
        parameters: [adminId("userId")],
      }),
    },
    "/admin/clusters": {
      post: operation({ tags: "Administration", summary: "Add a Proxmox cluster", body: { type: "object", additionalProperties: true }, success: 201 }),
    },
    "/admin/clusters/{clusterId}": {
      patch: operation({ tags: "Administration", summary: "Update a Proxmox cluster", parameters: [adminId("clusterId")], body: { type: "object", additionalProperties: true } }),
      delete: operation({ tags: "Administration", summary: "Delete a Proxmox cluster", parameters: [adminId("clusterId")], success: 204 }),
    },
    "/admin/clusters/{clusterId}/{operation}": {
      post: operation({
        tags: "Administration",
        summary: "Test or synchronize a Proxmox cluster",
        parameters: [
          adminId("clusterId"),
          { name: "operation", in: "path", required: true, schema: { type: "string", enum: ["test", "sync"] } },
        ],
      }),
    },
    "/admin/clusters/{clusterId}/iso-storage-candidates": {
      get: operation({
        tags: "Administration",
        summary: "List ISO-capable Proxmox storage candidates",
        parameters: [adminId("clusterId")],
      }),
    },
    "/admin/assignments": {
      post: operation({
        tags: "Administration",
        summary: "Directly assign a VM or container to a customer",
        body: { type: "object", additionalProperties: true },
        success: 201,
      }),
    },
    "/admin/resources/{resourceId}/assignment": {
      patch: operation({
        tags: "Administration",
        summary: "Update a direct assignment and permission policy",
        parameters: [resourceId],
        body: { type: "object", additionalProperties: true },
      }),
      delete: operation({
        tags: "Administration",
        summary: "Remove a direct assignment",
        parameters: [resourceId],
        success: 204,
      }),
    },
    "/admin/iso-policies": {
      post: operation({ tags: "Administration", summary: "Create an ISO storage policy", body: { type: "object", additionalProperties: true }, success: 201 }),
    },
    "/admin/iso-policies/{policyId}": {
      patch: operation({ tags: "Administration", summary: "Update an ISO storage policy", parameters: [adminId("policyId")], body: { type: "object", additionalProperties: true } }),
      delete: operation({ tags: "Administration", summary: "Delete an ISO storage policy", parameters: [adminId("policyId")], success: 204 }),
    },
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "Nimbus opaque token",
        description: "Use a short-lived nmb_at_ native access token or an administrator-enabled nmb_key_ integration key. Never send an nmb_rt_ refresh token as a bearer credential.",
      },
    },
    responses: {
      BadRequest: response("The request was invalid.", { $ref: "#/components/schemas/Error" }),
      Unauthorized: response("Authentication is missing, invalid, or expired.", { $ref: "#/components/schemas/Error" }),
      Forbidden: response("The authenticated user is not allowed to perform this operation.", { $ref: "#/components/schemas/Error" }),
      NotFound: response("The object is absent or deliberately hidden by tenant isolation.", { $ref: "#/components/schemas/Error" }),
      Conflict: response("The request conflicts with current resource or task state.", { $ref: "#/components/schemas/Error" }),
      RateLimited: {
        description: "The operation was rate limited.",
        headers: { "Retry-After": { schema: { type: "integer" } } },
        content: json({ $ref: "#/components/schemas/Error" }),
      },
    },
    schemas: {
      Error: {
        type: "object",
        required: ["error"],
        properties: {
          error: { type: "string" },
          message: { type: "string" },
          requestId: { type: "string" },
        },
      },
      MfaChallenge: {
        type: "object",
        required: ["mfaRequired", "challengeToken", "expiresAt"],
        properties: {
          mfaRequired: { type: "boolean", const: true },
          challengeToken: { type: "string" },
          expiresAt: { type: "integer" },
        },
      },
      DeviceSession: {
        type: "object",
        required: ["id", "kind", "deviceName", "platform", "createdAt", "lastSeenAt", "expiresAt"],
        properties: {
          id: { type: "string" },
          kind: { type: "string", const: "api" },
          current: { type: "boolean" },
          deviceName: { type: "string" },
          platform: { type: "string" },
          appVersion: { type: ["string", "null"] },
          ipAddress: { type: ["string", "null"] },
          createdAt: { type: "integer" },
          lastSeenAt: { type: "integer" },
          accessExpiresAt: { type: "integer" },
          expiresAt: { type: "integer" },
        },
      },
      TokenResponse: {
        type: "object",
        required: [
          "tokenType",
          "accessToken",
          "accessTokenExpiresAt",
          "refreshToken",
          "refreshTokenExpiresAt",
          "session",
          "user",
        ],
        properties: {
          tokenType: { type: "string", const: "Bearer" },
          accessToken: { type: "string" },
          accessTokenExpiresAt: { type: "integer" },
          refreshToken: { type: "string" },
          refreshTokenExpiresAt: { type: "integer" },
          session: { $ref: "#/components/schemas/DeviceSession" },
          user: { type: "object", additionalProperties: true },
          apiVersion: { type: "string", const: "v1" },
          demoReadOnly: { type: "boolean" },
        },
      },
      Resource: {
        type: "object",
        required: ["id", "clusterId", "node", "type", "vmid", "status"],
        properties: {
          id: { type: "string" },
          clusterId: { type: "string" },
          node: { type: "string" },
          type: { type: "string", enum: ["qemu", "lxc"] },
          vmid: { type: "integer" },
          name: { type: "string" },
          status: { type: "string" },
          permissions: { type: "array", items: { type: "string" } },
        },
        additionalProperties: true,
      },
      Task: {
        type: "object",
        required: ["id", "action", "state", "completed"],
        properties: {
          id: { type: "string" },
          resourceId: { type: ["string", "null"] },
          action: { type: "string" },
          state: { type: "string" },
          completed: { type: "boolean" },
          success: { type: ["boolean", "null"] },
          message: { type: "string" },
        },
        additionalProperties: true,
      },
    },
  },
};
