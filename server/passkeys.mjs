import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

function unavailable() {
  throw Object.assign(new Error("Passkeys are not configured for this Nimbus Direct instance"), {
    status: 409,
    code: "passkeys_not_configured",
  });
}

export function createPasskeyService(configuration) {
  const enabled = Boolean(configuration?.enabled);
  const rpID = configuration?.rpId || "";
  const rpName = configuration?.rpName || "Nimbus Direct";
  const origin = configuration?.origin || "";

  function requireEnabled() {
    if (!enabled) unavailable();
  }

  return {
    enabled,
    rpID,
    origin,

    async registrationOptions(user, existing = []) {
      requireEnabled();
      return generateRegistrationOptions({
        rpName,
        rpID,
        userName: user.email,
        userDisplayName: user.display_name || user.displayName || user.email,
        userID: new Uint8Array(Buffer.from(user.id, "base64url")),
        attestationType: "none",
        excludeCredentials: existing.map((credential) => ({
          id: credential.id,
          transports: credential.transports,
        })),
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
        },
        supportedAlgorithmIDs: [-7, -257],
      });
    },

    async verifyRegistration({ response, expectedChallenge }) {
      requireEnabled();
      return verifyRegistrationResponse({
        response,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
      });
    },

    async authenticationOptions() {
      requireEnabled();
      return generateAuthenticationOptions({
        rpID,
        allowCredentials: [],
        userVerification: "required",
      });
    },

    async verifyAuthentication({ response, expectedChallenge, passkey }) {
      requireEnabled();
      return verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
        credential: {
          id: passkey.id,
          publicKey: new Uint8Array(passkey.publicKey),
          counter: passkey.counter,
          transports: passkey.transports,
        },
      });
    },
  };
}
