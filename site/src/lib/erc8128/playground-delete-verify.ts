import {
  type SetHeadersFn,
  type VerifyFailReason,
  type VerifyMessageFn,
  verifyRequest
} from "@slicekit/erc8128"

type StorageMode = "none" | "redis" | "postgres"

type NonceEntry = {
  expiresAt: number
}

const nonceStores = new Map<StorageMode, Map<string, NonceEntry>>()

function getNonceStore(mode: StorageMode) {
  let store = nonceStores.get(mode)
  if (!store) {
    store = new Map()
    nonceStores.set(mode, store)
  }
  return store
}

function sweep(store: Map<string, NonceEntry>) {
  const now = Date.now()
  for (const [key, entry] of store) {
    if (entry.expiresAt <= now) {
      store.delete(key)
    }
  }
}

export type DeleteVerifySuccess = {
  ok: true
  address: string
  chainId: number
  label: string
  components: string[]
  binding: "request-bound" | "class-bound"
  replayable: boolean
  params: {
    created: number
    expires: number
    keyid: string
    nonce?: string
  }
}

export type DeleteVerifyFailure = {
  ok: false
  reason: VerifyFailReason
  detail?: string
}

export async function verifyDeletePlaygroundRequest(args: {
  request: Request
  storageMode: StorageMode
  verifyMessage: VerifyMessageFn
  setHeaders?: SetHeadersFn
}): Promise<DeleteVerifySuccess | DeleteVerifyFailure> {
  const { request, storageMode, verifyMessage, setHeaders } = args
  const store = getNonceStore(storageMode)

  sweep(store)

  const result = await verifyRequest({
    request,
    verifyMessage,
    nonceStore: {
      async consume(key, ttlSeconds) {
        sweep(store)
        if (store.has(key)) return false
        store.set(key, {
          expiresAt: Date.now() + Math.max(0, ttlSeconds) * 1000
        })
        return true
      }
    },
    policy: {
      replayable: false,
      classBoundPolicies: [],
      maxValiditySec: 300,
      clockSkewSec: 30
    },
    setHeaders
  })

  if (!result.ok) {
    return result
  }

  return {
    ok: true,
    address: result.address,
    chainId: result.chainId,
    label: result.label,
    components: result.components,
    binding: result.binding,
    replayable: result.replayable,
    params: {
      created: result.params.created,
      expires: result.params.expires,
      keyid: result.params.keyid.toLowerCase(),
      ...(result.params.nonce ? { nonce: result.params.nonce } : {})
    }
  }
}
