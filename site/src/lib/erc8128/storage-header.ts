export type StorageMode = "none" | "redis" | "postgres"

export const STORAGE_HEADER = "x-erc8128-storage"

const VALID_MODES = new Set<StorageMode>(["none", "redis", "postgres"])

export function parseStorageMode(
  headers: Headers,
  fallback: StorageMode = "none"
): StorageMode {
  const raw = headers.get(STORAGE_HEADER)?.toLowerCase().trim()
  if (raw && VALID_MODES.has(raw as StorageMode)) return raw as StorageMode
  return fallback
}
