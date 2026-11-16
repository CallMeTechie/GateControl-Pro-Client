# xterm.js (vendored)

| Field | Value |
|---|---|
| Source | npm `@xterm/xterm@5.5.0`, `@xterm/addon-fit@0.10.0` (the same version as GateControl's server) |
| Integrity | `@xterm/xterm@5.5.0`: `sha512-hqJHYaQb5OptNunnyAnkHyM8aCjZ1MEIDTQu1iIbbTD/xops91NB5yq1ZK/dC2JDbVWtF23zUtl9JE2NqwT87A==` · `@xterm/addon-fit@0.10.0`: `sha512-UFYkDm4HUahf2lnEyHvio51TNGiLK66mqP2JoATy7hRZeXaGMRDr00JiSF7m63vR5WKATF605yEggJKsw0JpMQ==` (checked against the tarballs) |
| Files | `lib/xterm.js`, `css/xterm.css`, `LICENSE` (MIT) · `lib/addon-fit.js`, its `LICENSE` as `LICENSE-addon-fit` (MIT) |
| Used by | the SSH terminal window of „Fernzugriff“ (`src/renderer/terminal.html`, `terminal.js`) |

The trailing `//# sourceMappingURL=…` line was removed from both scripts (the maps are not shipped); nothing else was
changed. No CDN and no server page: the terminal window loads these files from the app package.

## Content Security Policy

The terminal window allows only `default-src 'self'`. The DOM renderer of xterm.js writes two `<style>` elements of
its own, which such a policy blocks; `terminal.js` hands their text to constructed style sheets
(`document.adoptedStyleSheets`) instead, which the policy does not cover (no inline style is allowed).
