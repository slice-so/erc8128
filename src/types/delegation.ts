import type {
  Address,
  ComponentIdentifier,
  CoveredComponent,
  Hex,
  SfDictionary
} from "./core"
import type { EthHttpSigner } from "./signing"

export type AccountIdentity = { chainId: number; address: Address }

export type DelegationGrant = {
  fieldValue: string
  grantSignatureInput: string
  grantSignatureB64: string
}

export type ParsedDelegationField = {
  fieldValue: string
  root: AccountIdentity
  delegate: AccountIdentity
  delegateKeyType?: "eoa"
  audiences: string[]
  id: Hex
  epoch: number
  maxAge?: number
  allowReplayable: boolean
  components: ComponentIdentifier[]
  scopes: string[]
  members: SfDictionary
}

export type DelegationGrantBuildArgs = {
  root: AccountIdentity
  delegate: AccountIdentity
  delegateKeyType?: "eoa"
  audiences: readonly string[]
  id: Hex | Uint8Array
  epoch: number
  created?: number
  expires: number
  maxAge?: number
  allowReplayable?: true
  components?: readonly CoveredComponent[]
  scopes?: readonly string[]
}

export type PreparedDelegationGrant = {
  fieldValue: string
  signatureBase: Uint8Array
  signatureParamsValue: string
  params: {
    created: number
    expires: number
    keyid: string
    tag: "erc8128-delegation"
  }
}

export type DelegationRevocationContext = {
  authority: { address: Address; chainId: number }
  request: Request
  field: ParsedDelegationField
  grant: DelegationGrant
  grantCreated: number
  grantExpires: number
}

export type DelegationRevocationVerifier = (
  context: DelegationRevocationContext
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
  audience?: string | string[] | ((request: Request) => string)
  grantMaxValiditySec?: number
  revocation: {
    authority: { address: Address; chainId: number }
    verify: DelegationRevocationVerifier
  }
  grantCache?: DelegationGrantCache
  grantCacheTtlSec?: number
}

export type SignDelegationGrantArgs = DelegationGrantBuildArgs & {
  signer: EthHttpSigner
}
