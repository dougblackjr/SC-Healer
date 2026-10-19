/* Run from a trusted local copy in DevTools on the affected HTTPS origin.
 * Keep server-side sessions invalidated and PHP stopped. See README first.
 * No network requests, automatic removal, or worker registration.
 */
(() => {
  "use strict";
  const scripts = registration => [...new Set(
    [registration.active, registration.waiting, registration.installing]
      .filter(Boolean).map(worker => worker.scriptURL)
  )].sort();
  const same = (left, right) => JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
  const validateURL = value => {
    const url = new URL(value);
    if (url.origin !== location.origin || url.href !== value) {
      throw new Error("Use an exact absolute URL on this origin.");
    }
  };
  const api = {
    async inspect() {
      if (!isSecureContext || !("serviceWorker" in navigator)) {
        throw new Error("Open the affected HTTPS origin in a browser with service worker support.");
      }
      const registrations = await navigator.serviceWorker.getRegistrations();
      return {
        origin: location.origin,
        controller: navigator.serviceWorker.controller?.scriptURL ?? null,
        workers: registrations.map(registration => ({
          scope: registration.scope, scriptURLs: scripts(registration)
        })),
        cacheNames: "caches" in globalThis ? await caches.keys() : [],
        next: "Review exact worker URLs. Removal affects only this browser profile and origin."
      };
    },
    async removeWorkers(selections) {
      if (!Array.isArray(selections) || selections.length === 0) throw new Error("Select exact workers first.");
      const registrations = await navigator.serviceWorker.getRegistrations();
      const selected = [];
      const seen = new Set();
      for (const selection of selections) {
        validateURL(selection.scope);
        if (!Array.isArray(selection.scriptURLs) || selection.scriptURLs.length === 0) {
          throw new Error("Include the scriptURLs returned by inspect().");
        }
        selection.scriptURLs.forEach(validateURL);
        if (seen.has(selection.scope)) throw new Error("Duplicate scope.");
        seen.add(selection.scope);
        const registration = registrations.find(item => item.scope === selection.scope);
        if (!registration || !same(scripts(registration), selection.scriptURLs)) {
          throw new Error("Registration changed. Inspect again before removing anything.");
        }
        selected.push({registration, scriptURLs: [...selection.scriptURLs]});
      }
      const results = [];
      for (const {registration, scriptURLs} of selected) {
        if (!same(scripts(registration), scriptURLs)) {
          throw new Error("Registration changed during removal. Inspect again; earlier selections may already be unregistered.");
        }
        results.push({ scope: registration.scope, unregisterRequested: await registration.unregister() });
      }
      return { results, next: "Close EVERY tab/window for this origin. Check again before logging in. Existing controlled pages and ongoing work can survive unregister()." };
    },
    async removeCaches(names) {
      if (!Array.isArray(names) || !names.length || !names.every(name => typeof name === "string")) {
        throw new Error("Select exact cache names first.");
      }
      const available = await caches.keys();
      if (!names.every(name => available.includes(name))) throw new Error("Cache list changed; inspect again.");
      return Promise.all([...new Set(names)].map(async name => ({ name, deleted: await caches.delete(name) })));
    }
  };
  Object.defineProperty(globalThis, "scHealerBrowser", { value: Object.freeze(api), configurable: true });
  console.info("SC Healer loaded. Start with: await scHealerBrowser.inspect()");
})();
