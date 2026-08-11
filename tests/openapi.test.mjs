import test from "node:test";
import assert from "node:assert/strict";
import { nimbusOpenApi } from "../server/openapi.mjs";

test("Nimbus API publishes a versioned mobile and administration contract", () => {
  assert.equal(nimbusOpenApi.openapi, "3.1.0");
  assert.equal(nimbusOpenApi.info.version, "1.2.0");
  assert.deepEqual(nimbusOpenApi.security, [{ bearerAuth: [] }]);
  assert.deepEqual(nimbusOpenApi.paths["/auth/token"].post.security, []);
  assert.deepEqual(nimbusOpenApi.paths["/auth/refresh"].post.security, []);
  assert.equal(nimbusOpenApi.components.securitySchemes.bearerAuth.scheme, "bearer");

  for (const path of [
    "/me",
    "/api-keys",
    "/api-keys/preview",
    "/api-keys/{keyId}",
    "/security/passkeys/registration/options",
    "/security/passkeys/registration/verify",
    "/security/passkeys/{passkeyId}",
    "/resources",
    "/resources/refresh",
    "/resources/{resourceId}",
    "/resources/{resourceId}/actions",
    "/resources/{resourceId}/snapshots",
    "/resources/{resourceId}/media",
    "/tasks",
    "/notifications",
    "/maintenance",
    "/support/tickets",
    "/admin/state",
    "/admin/assignments",
    "/admin/users/{userId}/api-access",
    "/admin/users/{userId}/passkeys/reset",
    "/admin/users/{userId}/api-keys/{keyId}",
  ]) {
    assert.ok(nimbusOpenApi.paths[path], `missing OpenAPI path ${path}`);
  }

  const serialized = JSON.stringify(nimbusOpenApi);
  assert.equal(serialized.includes("tokenSecret"), false);
  assert.equal(serialized.includes("PVEAPIToken"), false);
});
