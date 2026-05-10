export type StorageMode = "redis" | "postgres"

export interface SecondaryStorage {
  get(key: string): Promise<string | null>
  getMany?(keys: string[]): Promise<(string | null)[]>
  mget?(keys: string[]): Promise<(string | null)[]>
  getMultiple?(keys: string[]): Promise<(string | null)[]>
  set(key: string, value: string, ttlSec?: number): Promise<void>
  delete(key: string): Promise<void>
  setIfNotExists?(key: string, value: string, ttlSec?: number): Promise<boolean>
}

export interface RequestScopedSecondaryStorage extends SecondaryStorage {
  close(): Promise<void>
}

export interface RedisSecondaryStorageOptions {
  connectionString: string
  keyPrefix?: string
}
