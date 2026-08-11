import type {
  Address,
  ComponentIdentifier,
  CoveredComponent,
  Hex
} from "./core"
import type { SignerClientOptions } from "./signing"

export type DelegationAudiencePolicy = {
  /** Permit canonical HTTP loopback origins for explicit local development. */
  allowLoopbackAudiences?: boolean
}

export type AccountIdentity = { chainId: number; address: Address }

/** The exact EIP-712 Delegation value defined by the delegated extension. */
export type Delegation = {
  issuer: string
  delegate: string
  audiences: string[]
  id: Hex
  epoch: number
  validAfter: number
  validUntil: number
  maxRequestValiditySeconds: number
  delegateIsEOA: boolean
  requireNonReplayable: boolean
  requiredComponents: string[]
  permissions: string[]
  parentGrantHash: Hex
}

/** One signed EIP-712 grant, embedded as one deterministic-CBOR link. */
export type DelegationLink = {
  grant: Delegation
  signature: Hex
}

export type DelegationChain = {
  links: DelegationLink[]
}

export type DelegationGrantBuildArgs = DelegationAudiencePolicy & {
  issuer: AccountIdentity
  delegate: AccountIdentity
  audiences: readonly string[]
  id: Hex | Uint8Array
  epoch: number
  validAfter?: number
  validUntil: number
  maxRequestValiditySeconds: number
  delegateIsEOA: boolean
  requireNonReplayable: boolean
  requiredComponents?: readonly CoveredComponent[]
  permissions?: readonly string[]
  parentGrantHash?: Hex
}

export type DelegationTypedData = {
  domain: {
    name: "ERC-8128 Delegation"
    version: "1"
    chainId: number
  }
  types: {
    Delegation: readonly [
      { readonly name: "issuer"; readonly type: "string" },
      { readonly name: "delegate"; readonly type: "string" },
      { readonly name: "audiences"; readonly type: "string[]" },
      { readonly name: "id"; readonly type: "bytes32" },
      { readonly name: "epoch"; readonly type: "uint64" },
      { readonly name: "validAfter"; readonly type: "uint64" },
      { readonly name: "validUntil"; readonly type: "uint64" },
      {
        readonly name: "maxRequestValiditySeconds"
        readonly type: "uint32"
      },
      { readonly name: "delegateIsEOA"; readonly type: "bool" },
      { readonly name: "requireNonReplayable"; readonly type: "bool" },
      { readonly name: "requiredComponents"; readonly type: "string[]" },
      { readonly name: "permissions"; readonly type: "string[]" },
      { readonly name: "parentGrantHash"; readonly type: "bytes32" }
    ]
  }
  primaryType: "Delegation"
  message: Omit<Delegation, "epoch" | "validAfter" | "validUntil"> & {
    epoch: bigint
    validAfter: bigint
    validUntil: bigint
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

export type DelegationStatus =
  | "valid"
  | "revoked"
  | "epoch-mismatch"
  | "unavailable"

export type DelegationStatusVerifier = (
  contexts: readonly DelegationStatusContext[]
) => readonly DelegationStatus[] | Promise<readonly DelegationStatus[]>

export interface DelegationGrantCache {
  get(key: string): true | undefined | Promise<true | undefined>
  set(key: string, expiresAt: number): void | Promise<void>
}

export type DelegationPolicy = {
  allowLoopbackAudiences?: boolean
  grantCache?: DelegationGrantCache
  /** Optional finite non-negative proof-cache TTL. */
  grantCacheTtlSec?: number
  maxChainDepth?: number
  /** Optional finite non-negative cap on each grant validity window. */
  maxGrantValiditySec?: number
  requiredPermissions?: readonly string[]
  permissionsSupported?: boolean
  verifyStatuses: DelegationStatusVerifier
}

export type DelegatedSignerClientOptions = Omit<
  SignerClientOptions,
  "authorizationPolicy" | "authorizationExpiresAt"
> &
  DelegationAudiencePolicy

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
  effectiveAudiences: string[]
  effectiveRequiredComponents: ComponentIdentifier[]
  effectiveMaxRequestValiditySeconds: number
  effectiveRequireNonReplayable: boolean
  effectivePermissions: string[]
}
