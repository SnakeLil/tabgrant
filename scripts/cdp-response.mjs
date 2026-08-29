export function dispatchCdpResponse(serialized, pending) {
  if (typeof serialized !== "string" || !(pending instanceof Map)) return false;

  let message;
  try {
    message = JSON.parse(serialized);
  } catch {
    return false;
  }
  if (
    message === null ||
    typeof message !== "object" ||
    Array.isArray(message) ||
    !Number.isSafeInteger(message.id) ||
    message.id <= 0
  ) {
    return false;
  }

  const callback = pending.get(message.id);
  if (typeof callback !== "function") return false;
  pending.delete(message.id);
  callback(message);
  return true;
}
