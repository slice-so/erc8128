/**
 * In-memory DB adapter stub simulating Postgres-backed better-auth adapter.
 *
 * Used by the `postgres` storage mode for:
 * - Nonce store (findVerificationValue, createVerificationValue)
 * - Verification cache (findVerificationValue, createVerificationValue, deleteVerificationByIdentifier)
 * - Invalidation ops (findOne, findMany, create, update on erc8128Invalidation)
 *
 * Later this is replaced by a real Better Auth adapter backed by Postgres.
 */

interface VerificationRecord {
  id: string
  identifier: string
  value: string
  expiresAt: Date
}

interface InvalidationRecord {
  id: string
  keyId?: string
  signature?: string
  notBefore: number
  expiresAt?: number
  updatedAt: Date
}

let verificationIdCounter = 0
let invalidationIdCounter = 0

export interface AdapterStub {
  // Verification value methods (nonce store + cache)
  findVerificationValue(identifier: string): Promise<VerificationRecord | null>
  createVerificationValue(data: {
    identifier: string
    value: string
    expiresAt: Date
  }): Promise<VerificationRecord>
  deleteVerificationByIdentifier(identifier: string): Promise<void>

  // Generic adapter methods (invalidation ops)
  findOne(query: {
    model: string
    where: Array<{ field: string; operator: string; value: unknown }>
  }): Promise<Record<string, unknown> | null>
  findMany(query: {
    model: string
    where: Array<{ field: string; operator: string; value: unknown }>
  }): Promise<Array<Record<string, unknown>>>
  create(query: {
    model: string
    data: Record<string, unknown>
  }): Promise<Record<string, unknown>>
  update(query: {
    model: string
    where: Array<{ field: string; operator: string; value: unknown }>
    update: Record<string, unknown>
  }): Promise<Record<string, unknown> | null>
}

export function createAdapterStub(): AdapterStub {
  const verificationStore = new Map<string, VerificationRecord>()
  const invalidationStore = new Map<string, InvalidationRecord>()

  const isVerificationExpired = (record: VerificationRecord) =>
    record.expiresAt.getTime() <= Date.now()

  const matchesWhere = (
    record: Record<string, unknown>,
    where: Array<{ field: string; operator: string; value: unknown }>
  ): boolean =>
    where.every(({ field, value }) => {
      const recordValue = record[field]
      if (typeof recordValue === "string" && typeof value === "string") {
        return recordValue.toLowerCase() === value.toLowerCase()
      }
      return recordValue === value
    })

  return {
    async findVerificationValue(identifier) {
      const record = verificationStore.get(identifier)
      if (!record) return null
      if (isVerificationExpired(record)) {
        verificationStore.delete(identifier)
        return null
      }
      return record
    },

    async createVerificationValue(data) {
      const record: VerificationRecord = {
        id: `ver_${++verificationIdCounter}`,
        ...data
      }
      verificationStore.set(data.identifier, record)
      return record
    },

    async deleteVerificationByIdentifier(identifier) {
      verificationStore.delete(identifier)
    },

    async findOne({ model, where }) {
      if (model === "erc8128Invalidation") {
        for (const record of invalidationStore.values()) {
          if (matchesWhere(record as unknown as Record<string, unknown>, where))
            return record as unknown as Record<string, unknown>
        }
        return null
      }
      return null
    },

    async findMany({ model, where }) {
      if (model === "erc8128Invalidation") {
        const results: Array<Record<string, unknown>> = []
        for (const record of invalidationStore.values()) {
          if (matchesWhere(record as unknown as Record<string, unknown>, where))
            results.push(record as unknown as Record<string, unknown>)
        }
        return results
      }
      return []
    },

    async create({ model, data }) {
      if (model === "erc8128Invalidation") {
        const record: InvalidationRecord = {
          id: `inv_${++invalidationIdCounter}`,
          keyId: data.keyId as string | undefined,
          signature: data.signature as string | undefined,
          notBefore: (data.notBefore as number) ?? 0,
          expiresAt: data.expiresAt as number | undefined,
          updatedAt: (data.updatedAt as Date) ?? new Date()
        }
        invalidationStore.set(record.id, record)
        return record as unknown as Record<string, unknown>
      }
      return data
    },

    async update({ model, where, update: updateData }) {
      if (model === "erc8128Invalidation") {
        for (const [id, record] of invalidationStore) {
          if (
            matchesWhere(record as unknown as Record<string, unknown>, where)
          ) {
            const updated = { ...record, ...updateData } as InvalidationRecord
            invalidationStore.set(id, updated)
            return updated as unknown as Record<string, unknown>
          }
        }
      }
      return null
    }
  }
}
