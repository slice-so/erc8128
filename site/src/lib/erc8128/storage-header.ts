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

/**
 * Validate a storage mode from an env var, returning a safe default
 * if the value is missing or invalid. Prevents unsafe casts.
 */
export function parseStorageModeFromEnv(
  envValue: string | undefined,
  fallback: StorageMode = "none"
): StorageMode {
  if (!envValue) return fallback
  const normalized = envValue.toLowerCase().trim()
  if (VALID_MODES.has(normalized as StorageMode))
    return normalized as StorageMode
  return fallback
}
