import type {
  Address,
  ComponentIdentifier,
  CoveredComponent,
  Hex
} from "./core"

export type AccountIdentity = { chainId: number; address: Address }

/** The exact EIP-712 Delegation value defined by the delegated extension. */
export type Delegation = {
  root: string
  delegate: string
  aud: string[]
  id: Hex
  epoch: number
  created: number
  expires: number
  maxAge: number
  delegateIsEOA: boolean
  allowReplayable: boolean
  components: string[]
  scope: string[]
  parent: Hex
}

/** One signed EIP-712 grant, embedded as one ABI-encoded delegation link. */
export type DelegationLink = {
  grant: Delegation
  signature: Hex
}

export type DelegationChain = {
  links: DelegationLink[]
}

export type DelegationGrantBuildArgs = {
  root: AccountIdentity
  delegate: AccountIdentity
  audiences: readonly string[]
  id: Hex | Uint8Array
  epoch: number
  created?: number
  expires: number
  maxAge: number
  delegateIsEOA: boolean
  allowReplayable: boolean
  components?: readonly CoveredComponent[]
  scopes?: readonly string[]
  parent?: Hex
}

export type DelegationTypedData = {
  domain: {
    name: "ERC-8128 Delegation"
    version: "1"
    chainId: number
  }
  types: {
    Delegation: readonly [
      { readonly name: "root"; readonly type: "string" },
      { readonly name: "delegate"; readonly type: "string" },
      { readonly name: "aud"; readonly type: "string[]" },
      { readonly name: "id"; readonly type: "bytes32" },
      { readonly name: "epoch"; readonly type: "uint64" },
      { readonly name: "created"; readonly type: "uint64" },
      { readonly name: "expires"; readonly type: "uint64" },
      { readonly name: "maxAge"; readonly type: "uint32" },
      { readonly name: "delegateIsEOA"; readonly type: "bool" },
      { readonly name: "allowReplayable"; readonly type: "bool" },
      { readonly name: "components"; readonly type: "string[]" },
      { readonly name: "scope"; readonly type: "string[]" },
      { readonly name: "parent"; readonly type: "bytes32" }
    ]
  }
  primaryType: "Delegation"
  message: Omit<Delegation, "epoch" | "created" | "expires"> & {
    epoch: bigint
    created: bigint
    expires: bigint
  }
}

export type PreparedDelegationGrant = {
  grant: Delegation
  digest: Hex
  typedData: DelegationTypedData
}

export type DelegationStatusContext = {
  link: DelegationLink
  request: Request
}

export type DelegationStatusVerifier = (
  context: DelegationStatusContext
) =>
  | "valid"
  | "revoked"
  | "epoch-mismatch"
  | "unavailable"
  | Promise<"valid" | "revoked" | "epoch-mismatch" | "unavailable">

export interface DelegationGrantCache {
  get(key: string): true | undefined | Promise<true | undefined>
  set(key: string, expiresAt: number): void | Promise<void>
}

export type DelegationPolicy = {
  grantCache?: DelegationGrantCache
  grantCacheTtlSec?: number
  maxChainDepth?: number
  maxGrantValiditySec?: number
  requiredScopes?: readonly string[]
  scopeSupported?: boolean
  verifyStatus: DelegationStatusVerifier
}

export type DelegationSigner = AccountIdentity & {
  signTypedData: (typedData: DelegationTypedData) => Promise<Hex>
}

export type SignDelegationGrantArgs = DelegationGrantBuildArgs & {
  signer: DelegationSigner
}

export type ParsedDelegationField = {
  chain: DelegationChain
  fieldValue: string
}

export type ResolvedDelegationChain = ParsedDelegationField & {
  effectiveAudience: string[]
  effectiveComponents: ComponentIdentifier[]
  effectiveMaxAge: number
  effectiveReplayable: boolean
  effectiveScope: string[]
}
