(function initializePrivacyPage() {
  const storageKey = "nimbus-direct-language";
  const supportedLanguages = new Set(["en", "de"]);

  function browserLanguage() {
    const preferred = navigator.languages?.length ? navigator.languages : [navigator.language || "en"];
    return preferred.some((language) => String(language).toLowerCase().startsWith("de")) ? "de" : "en";
  }

  function initialLanguage() {
    try {
      const stored = String(localStorage.getItem(storageKey) || "system").toLowerCase();
      if (supportedLanguages.has(stored)) return stored;
    } catch {
      // The browser language remains available when storage is blocked.
    }
    return browserLanguage();
  }

  function setLanguage(language, { persist = false } = {}) {
    const selected = supportedLanguages.has(language) ? language : "en";
    document.documentElement.lang = selected;
    document.title = selected === "de"
      ? "Datenschutz der Nimbus Direct App"
      : "Nimbus Direct App Privacy";

    document.querySelectorAll("[data-language-root]").forEach((element) => {
      element.hidden = element.dataset.languageRoot !== selected;
    });
    document.querySelectorAll("[data-privacy-language]").forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.privacyLanguage === selected));
    });
    document.querySelectorAll("[data-en][data-de]").forEach((element) => {
      element.textContent = element.dataset[selected];
    });

    if (persist) {
      try { localStorage.setItem(storageKey, selected); } catch { /* Keep the in-memory selection. */ }
    }
  }

  document.querySelectorAll("[data-privacy-language]").forEach((button) => {
    button.addEventListener("click", () => setLanguage(button.dataset.privacyLanguage, { persist: true }));
  });

  const appearanceButton = document.querySelector("#privacyAppearance");
  const appearanceIcons = { system: "◐", light: "☀", dark: "☾" };
  const appearanceNames = {
    en: { system: "System", light: "Light", dark: "Dark" },
    de: { system: "System", light: "Hell", dark: "Dunkel" },
  };

  function updateAppearanceButton() {
    if (!appearanceButton || !window.NimbusAppearance) return;
    const mode = window.NimbusAppearance.get();
    const language = document.documentElement.lang === "de" ? "de" : "en";
    const prefix = language === "de" ? "Darstellung" : "Appearance";
    const label = `${prefix}: ${appearanceNames[language][mode]}`;
    appearanceButton.setAttribute("aria-label", label);
    appearanceButton.title = label;
    appearanceButton.querySelector("span").textContent = appearanceIcons[mode];
  }

  appearanceButton?.addEventListener("click", () => {
    if (!window.NimbusAppearance) return;
    const order = ["system", "light", "dark"];
    const current = window.NimbusAppearance.get();
    window.NimbusAppearance.set(order[(order.indexOf(current) + 1) % order.length]);
    updateAppearanceButton();
  });

  window.addEventListener("nimbusappearancechange", updateAppearanceButton);
  document.querySelectorAll("[data-privacy-language]").forEach((button) => {
    button.addEventListener("click", updateAppearanceButton);
  });

  setLanguage(initialLanguage());
  updateAppearanceButton();
}());
