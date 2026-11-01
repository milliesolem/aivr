// Minimal, faithful browser-global shim so the REAL, unmodified
// `react-secure-storage` npm package runs under Node.
//
// Nothing here weakens the library. It only supplies the DOM/`navigator`
// values a normal browser would. In particular `canvas.toDataURL()` returns a
// value that is *constant for a given OS + browser + GPU* — exactly how a real
// canvas fingerprint behaves (two users on the same platform get the same
// string). The whole point of the finding is that none of these inputs are
// secret and the library crushes them down to a 32-bit non-crypto hash.

class LocalStorageShim {
  // Methods live on the prototype, so `Object.entries(localStorage)` returns
  // only the stored key/value pairs — matching real Web Storage semantics,
  // which `react-secure-storage` relies on when it preloads the store.
  getItem(k) {
    return Object.prototype.hasOwnProperty.call(this, k) ? this[k] : null;
  }
  setItem(k, v) {
    this[k] = String(v);
  }
  removeItem(k) {
    delete this[k];
  }
  clear() {
    for (const k of Object.keys(this)) delete this[k];
  }
}

function makeCanvas(dataUrl) {
  const ctx = {
    textBaseline: "",
    font: "",
    fillStyle: "",
    fillRect() {},
    fillText() {},
  };
  return {
    getContext(type) {
      return type === "2d" ? ctx : null;
    },
    toDataURL() {
      return dataUrl;
    },
  };
}

/**
 * Install browser globals for a concrete, realistic browser profile, then you
 * may `require("react-secure-storage")`.
 *
 * @param {object} p
 * @param {string} p.userAgent      e.g. a normal Chrome UA (sent in every HTTP request)
 * @param {string} p.hostname       the app's own domain
 * @param {number} p.colorDepth     window.screen.colorDepth (almost always 24)
 * @param {string} p.language       navigator.language, e.g. "en-US"
 * @param {string} p.canvasDataUrl  canvas.toDataURL() for this OS/browser/GPU
 * @param {boolean} p.cookieEnabled navigator.cookieEnabled
 */
function installBrowserEnv(p) {
  const navigator = {
    userAgent: p.userAgent,
    language: p.language,
    plugins: { length: 0 }, // modern browsers expose no enumerable plugins
    cookieEnabled: p.cookieEnabled !== false,
  };
  const screen = { colorDepth: p.colorDepth, width: 1920, height: 1080 };
  const localStorage = new LocalStorageShim();

  global.navigator = navigator;
  global.localStorage = localStorage;
  global.sessionStorage = new LocalStorageShim();
  global.window = {
    location: { hostname: p.hostname },
    navigator,
    screen,
    localStorage,
    sessionStorage: global.sessionStorage,
  };
  global.document = {
    createElement(tag) {
      if (tag === "canvas") return makeCanvas(p.canvasDataUrl);
      return {};
    },
  };
  return { localStorage };
}

module.exports = { installBrowserEnv, LocalStorageShim };
