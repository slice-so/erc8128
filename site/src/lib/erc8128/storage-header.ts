import type { StorageMode } from "../../types"

export const STORAGE_HEADER = "x-erc8128-storage"

const VALID_MODES = new Set<StorageMode>(["redis", "postgres"])

export function parseStorageMode(
  headers: Headers,
  fallback: StorageMode = "postgres",
  allowHeaderOverride = false
): StorageMode {
  if (!allowHeaderOverride) return fallback
  const raw = headers.get(STORAGE_HEADER)?.toLowerCase().trim()
  if (raw && VALID_MODES.has(raw as StorageMode)) return raw as StorageMode
  return fallback
}

export function parseConfiguredStorageMode(
  value: string | undefined,
  fallback: StorageMode = "postgres"
): StorageMode {
  const normalized = value?.toLowerCase().trim()
  return normalized && VALID_MODES.has(normalized as StorageMode)
    ? (normalized as StorageMode)
    : fallback
}
