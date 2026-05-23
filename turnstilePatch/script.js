// turnstilePatch — runs at document_start in MAIN world, in every frame.
// Reason: Chrome DevTools Protocol Input.dispatchMouseEvent leaks itself
// because screenX/screenY come through as 0/0 (the bug catalogued by
// TheFalloutOf76/CDP-bug-MouseEvent-.screenX-.screenY-patcher). Cloudflare
// Turnstile uses that signal to flag automation. We override the getters so
// they return random plausible coordinates, which is enough to satisfy the
// non-interactive challenge.

(function () {
  try {
    const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
    const sx = rand(800, 1200);
    const sy = rand(400, 700);

    // Patch the prototypes — affects every MouseEvent and PointerEvent instance.
    for (const proto of [window.MouseEvent && window.MouseEvent.prototype,
                         window.PointerEvent && window.PointerEvent.prototype]) {
      if (!proto) continue;
      try {
        Object.defineProperty(proto, "screenX", { get() { return sx; }, configurable: true });
        Object.defineProperty(proto, "screenY", { get() { return sy; }, configurable: true });
      } catch (_) { /* ignore — already patched */ }
    }
  } catch (_) {}
})();
