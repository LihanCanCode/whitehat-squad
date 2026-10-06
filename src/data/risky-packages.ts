/**
 * Package + version pairs that were publicly reported as compromised, malicious or sabotaged.
 * Only exact versions are listed, and only ones the author is confident about; the
 * list is deliberately small. Absence from this list does NOT mean a version is safe.
 */
export interface RiskyPackage {
  readonly name: string;
  readonly versions: readonly string[];
  readonly reason: string;
}

export const RISKY_PACKAGES: readonly RiskyPackage[] = [
  { name: "event-stream", versions: ["3.3.6"], reason: "2018: maintainer handed over, flatmap-stream payload stole Copay bitcoin wallet keys" },
  { name: "flatmap-stream", versions: ["0.1.1"], reason: "2018: malicious payload injected via event-stream" },
  { name: "ua-parser-js", versions: ["0.7.29", "0.8.0", "1.0.0"], reason: "2021: account hijacked, versions shipped a cryptominer and password stealer" },
  { name: "coa", versions: ["2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"], reason: "2021: account hijacked, versions installed a password stealer" },
  { name: "rc", versions: ["1.2.9", "1.3.9", "2.3.9"], reason: "2021: account hijacked, versions installed a password stealer" },
  { name: "colors", versions: ["1.4.1", "1.4.2"], reason: "2022: maintainer sabotage, infinite loop that hangs your app" },
  { name: "faker", versions: ["6.6.6"], reason: "2022: maintainer sabotage, package emptied and replaced with a stub" },
  { name: "node-ipc", versions: ["10.1.1", "10.1.2", "10.1.3", "11.0.0"], reason: "2022: protestware, overwrote files or dropped a message file on machines geolocated to Russia/Belarus" },
  { name: "eslint-scope", versions: ["3.7.2"], reason: "2018: maintainer npm token stolen, version stole npm credentials" },
  { name: "@solana/web3.js", versions: ["1.95.6", "1.95.7"], reason: "2024: publish access phished, versions exfiltrated private keys" },
  { name: "@lottiefiles/lottie-player", versions: ["2.0.5", "2.0.6", "2.0.7"], reason: "2024: maintainer account compromised, wallet-drainer injected" },
  { name: "@ledgerhq/connect-kit", versions: ["1.1.5", "1.1.6", "1.1.7"], reason: "2023: former employee phished, wallet-drainer injected" },
  // 2025 "Shai-Hulud" worm and the Sept 2025 maintainer-phishing compromise (qix et al.)
  { name: "@ctrl/tinycolor", versions: ["4.1.1", "4.1.2"], reason: "2025: Shai-Hulud npm worm, steals tokens and republishes itself" },
  { name: "eslint-config-prettier", versions: ["8.10.1", "9.1.1", "10.1.6", "10.1.7"], reason: "2025: maintainer phished, Windows malware loader in install script" },
  { name: "eslint-plugin-prettier", versions: ["4.2.2", "4.2.3"], reason: "2025: maintainer phished, Windows malware loader in install script" },
  { name: "synckit", versions: ["0.11.9"], reason: "2025: maintainer phished, Windows malware loader in install script" },
  { name: "@pkgr/core", versions: ["0.2.8"], reason: "2025: maintainer phished, Windows malware loader in install script" },
  { name: "napi-postinstall", versions: ["0.3.1"], reason: "2025: maintainer phished, Windows malware loader in install script" },
  { name: "chalk", versions: ["5.6.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "debug", versions: ["4.4.2"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "ansi-styles", versions: ["6.2.2"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "strip-ansi", versions: ["7.1.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "supports-color", versions: ["10.2.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "ansi-regex", versions: ["6.2.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "wrap-ansi", versions: ["9.0.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "slice-ansi", versions: ["7.1.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "color-convert", versions: ["3.1.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "color-name", versions: ["2.0.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "color-string", versions: ["2.1.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "has-ansi", versions: ["6.0.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "supports-hyperlinks", versions: ["4.1.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "chalk-template", versions: ["1.1.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "backslash", versions: ["0.2.1"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "error-ex", versions: ["1.3.3"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "is-arrayish", versions: ["0.3.3"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
  { name: "simple-swizzle", versions: ["0.2.3"], reason: "2025-09: maintainer phished, browser crypto-address swapper injected" },
];

const INDEX: ReadonlyMap<string, RiskyPackage> = new Map(RISKY_PACKAGES.map((p) => [p.name, p]));

/** Returns the advisory when this exact name@version is on the list. */
export function findRisky(name: string, version: string): RiskyPackage | undefined {
  const hit = INDEX.get(name);
  return hit && hit.versions.includes(version) ? hit : undefined;
}
