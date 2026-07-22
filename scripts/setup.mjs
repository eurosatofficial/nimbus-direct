import { loadEnv, readConfig } from "../server/config.mjs";
import { bootstrapStore, openStore } from "../server/store.mjs";

await loadEnv(new URL("../.env", import.meta.url));
const config = readConfig();
const store = await openStore(config.dataDir, { appSecret: config.appSecret });

try {
  if (store.hasUsers()) {
    console.log("Nimbus already has at least one user. No changes were made.");
    process.exitCode = 1;
  } else if (!config.bootstrap.email || !config.bootstrap.password) {
    console.error("Set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD in .env first.");
    process.exitCode = 1;
  } else {
    await bootstrapStore(store, config.bootstrap);
    console.log(`Platform administrator ${config.bootstrap.email} created. Remove bootstrap passwords from .env now.`);
  }
} finally {
  store.close();
}
