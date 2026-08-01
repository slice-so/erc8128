import type {
  Address,
  ComponentIdentifier,
  CoveredComponent,
  Hex,
  SfDictionary,
  SfMember
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
  maxAge?: number
  replayable: boolean
  components: ComponentIdentifier[]
  critical: string[]
  extensions: Record<string, SfMember>
  members: SfDictionary
}

export type DelegationGrantBuildArgs = {
  root: AccountIdentity
  delegate: AccountIdentity
  delegateKeyType?: "eoa"
  audiences: readonly string[]
  id: Hex | Uint8Array
  created?: number
  expires: number
  maxAge?: number
  replayable?: boolean
  components?: readonly CoveredComponent[]
  critical?: readonly string[]
  extensions?: Record<string, SfMember>
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

export type DelegationExtensionContext = {
  request: Request
  field: ParsedDelegationField
  member: SfMember
  grant: DelegationGrant
  grantCreated: number
  grantExpires: number
}

export type DelegationExtensionHandler = (
  context: DelegationExtensionContext
) =>
  | boolean
  | "unavailable"
  | { ok: boolean; detail?: string }
  | Promise<boolean | "unavailable" | { ok: boolean; detail?: string }>

export interface DelegationGrantCache {
  get(key: string): true | undefined | Promise<true | undefined>
  set(key: string, expiresAt: number): void | Promise<void>
}

export type DelegationPolicy = {
  audience?: string | string[] | ((request: Request) => string)
  grantMaxValiditySec?: number
  extensions?: Record<string, DelegationExtensionHandler>
  grantCache?: DelegationGrantCache
  grantCacheTtlSec?: number
}

export type SignDelegationGrantArgs = DelegationGrantBuildArgs & {
  signer: EthHttpSigner
}

export type RevocationExtension = {
  registry: Address
  chainId: number
  epoch: number
}
