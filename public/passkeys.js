function decodeBase64Url(value) {
  const base64 = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64Url(value) {
  const bytes = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function creationOptions(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    user: { ...options.user, id: decodeBase64Url(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    })),
  };
}

function requestOptions(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    })),
  };
}

function baseCredential(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

export function passkeysSupported() {
  return Boolean(window.PublicKeyCredential && navigator.credentials);
}

export async function createPasskey(options) {
  if (!passkeysSupported()) throw Object.assign(new Error("Passkeys are not supported by this browser"), { code: "passkeys_not_supported" });
  const credential = await navigator.credentials.create({ publicKey: creationOptions(options) });
  if (!credential) throw Object.assign(new Error("Passkey creation was cancelled"), { code: "passkey_cancelled" });
  const response = credential.response;
  return {
    ...baseCredential(credential),
    response: {
      attestationObject: encodeBase64Url(response.attestationObject),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      transports: typeof response.getTransports === "function" ? response.getTransports() : [],
      publicKeyAlgorithm: typeof response.getPublicKeyAlgorithm === "function" ? response.getPublicKeyAlgorithm() : undefined,
      publicKey: typeof response.getPublicKey === "function" && response.getPublicKey()
        ? encodeBase64Url(response.getPublicKey())
        : undefined,
    },
  };
}

export async function authenticateWithPasskey(options) {
  if (!passkeysSupported()) throw Object.assign(new Error("Passkeys are not supported by this browser"), { code: "passkeys_not_supported" });
  const credential = await navigator.credentials.get({ publicKey: requestOptions(options) });
  if (!credential) throw Object.assign(new Error("Passkey sign-in was cancelled"), { code: "passkey_cancelled" });
  const response = credential.response;
  return {
    ...baseCredential(credential),
    response: {
      authenticatorData: encodeBase64Url(response.authenticatorData),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle ? encodeBase64Url(response.userHandle) : undefined,
    },
  };
}
