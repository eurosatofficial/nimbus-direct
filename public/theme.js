(function initializeNimbusAppearance() {
  const storageKey = "nimbus-direct-appearance";
  const modes = ["system", "light", "dark"];
  const media = window.matchMedia("(prefers-color-scheme: dark)");

  function normalize(value) {
    return modes.includes(value) ? value : "system";
  }

  function resolved(mode) {
    return mode === "system" ? (media.matches ? "dark" : "light") : mode;
  }

  function apply(mode, { persist = false, notify = false } = {}) {
    const appearance = normalize(mode);
    const theme = resolved(appearance);
    document.documentElement.dataset.appearance = appearance;
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    const themeColor = document.querySelector('meta[name="theme-color"]');
    if (themeColor) themeColor.content = theme === "dark" ? "#0f1422" : "#f4f6fb";
    if (persist) {
      try {
        localStorage.setItem(storageKey, appearance);
      } catch {
        // Keep the in-memory choice when browser storage is unavailable.
      }
    }
    if (notify) {
      window.dispatchEvent(new CustomEvent("nimbusappearancechange", {
        detail: { appearance, theme },
      }));
    }
    return { appearance, theme };
  }

  let initial = "system";
  try {
    initial = normalize(localStorage.getItem(storageKey));
  } catch {
    // Browser privacy settings may block local storage. System mode still works.
  }
  apply(initial);

  const mediaChanged = () => {
    if (document.documentElement.dataset.appearance === "system") {
      apply("system", { notify: true });
    }
  };
  if (typeof media.addEventListener === "function") media.addEventListener("change", mediaChanged);
  else media.addListener(mediaChanged);

  window.NimbusAppearance = Object.freeze({
    modes: [...modes],
    get: () => normalize(document.documentElement.dataset.appearance),
    resolved: () => document.documentElement.dataset.theme || resolved("system"),
    set(mode) {
      const result = apply(mode, { persist: true, notify: true });
      return result.appearance;
    },
  });
}());
