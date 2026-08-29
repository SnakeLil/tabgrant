const BLOCKED_HTTP_ORIGINS = new Set([
  "https://chrome.google.com",
  "https://chromewebstore.google.com",
]);

export function grantableOrigin(rawUrl: string | undefined): string | undefined {
  if (!rawUrl) return undefined;
  try {
    const url = new URL(rawUrl);
    if (url.username || url.password) return undefined;
    if (
      url.protocol !== "https:" &&
      !(url.protocol === "http:" && isLoopbackHostname(url.hostname))
    )
      return undefined;
    if (BLOCKED_HTTP_ORIGINS.has(url.origin)) return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
}

export function sameOriginNavigation(currentOrigin: string, target: string): string | undefined {
  try {
    const url = new URL(target, `${currentOrigin}/`);
    if (url.href.length > 2_048 || grantableOrigin(url.href) !== currentOrigin) return undefined;
    return url.origin === currentOrigin ? url.href : undefined;
  } catch {
    return undefined;
  }
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === "localhost" || normalized.endsWith(".localhost") || normalized === "[::1]")
    return true;
  const octets = normalized.split(".");
  return (
    octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet)) &&
    Number(octets[0]) === 127
  );
}

export function isSensitiveControl(element: Element): boolean {
  if (!(element instanceof HTMLInputElement) && !(element instanceof HTMLTextAreaElement))
    return false;
  if (element instanceof HTMLInputElement && element.type.toLowerCase() === "password") return true;
  const autocompleteToken = element.autocomplete.toLowerCase().split(/\s+/).at(-1) ?? "";
  return (
    autocompleteToken === "current-password" ||
    autocompleteToken === "new-password" ||
    autocompleteToken === "one-time-code" ||
    autocompleteToken.startsWith("cc-")
  );
}
