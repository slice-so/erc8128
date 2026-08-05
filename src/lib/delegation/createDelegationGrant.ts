import type {
  Delegation,
  DelegationAudiencePolicy,
  DelegationChain,
  DelegationGrantBuildArgs,
  DelegationLink,
  Hex,
  PreparedDelegationGrant,
  SignDelegationGrantArgs
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { normalizeComponentIdentifier } from "../engine/componentIdentifier"
import { formatKeyId } from "../keyId"
import { bytesToHex, hexToBytes, unixNow } from "../utilities"
import {
  encodeDelegationLink,
  formatDelegationField,
  getDelegationTypedData,
  hashDelegation,
  parseDelegationField,
  serializeDelegationComponent,
  validateDelegation,
  ZERO_DELEGATION_PARENT
} from "./delegationField"
import { MAX_DELEGATION_LINK_BYTES } from "./limits"

/**
 * Absolute raw proof ceiling. The usable proof size is lower because the
 * complete deterministic-CBOR Delegation Link must fit within 8 KiB.
 */
export const maximumDelegationGrantSignatureBytes = MAX_DELEGATION_LINK_BYTES

export function buildDelegationGrant(
  args: DelegationGrantBuildArgs
): PreparedDelegationGrant {
  const id =
    args.id instanceof Uint8Array ? bytesToHex(args.id) : args.id.toLowerCase()
  const grant: Delegation = {
    issuer: formatKeyId(args.issuer.chainId, args.issuer.address),
    delegate: formatKeyId(args.delegate.chainId, args.delegate.address),
    audiences: [...args.audiences],
    id: id as Hex,
    epoch: args.epoch,
    validAfter: args.validAfter ?? unixNow(),
    validUntil: args.validUntil,
    maxRequestValiditySeconds: args.maxRequestValiditySeconds,
    delegateIsEOA: args.delegateIsEOA,
    requireNonReplayable: args.requireNonReplayable,
    requiredComponents: (args.requiredComponents ?? []).map((component) =>
      serializeDelegationComponent(normalizeComponentIdentifier(component))
    ),
    permissions: [...(args.permissions ?? [])],
    parentGrantHash: args.parentGrantHash ?? ZERO_DELEGATION_PARENT
  }
  const audiencePolicy = {
    allowLoopbackAudiences: args.allowLoopbackAudiences === true
  }
  validateDelegation(grant, audiencePolicy)
  const typedData = getDelegationTypedData(grant)
  return {
    grant,
    digest: hashDelegation(grant, audiencePolicy),
    typedData,
    ...(args.allowLoopbackAudiences === true
      ? { allowLoopbackAudiences: true }
      : {})
  }
}

export function completeDelegationGrant(
  prepared: PreparedDelegationGrant,
  signature: Hex | Uint8Array
): DelegationLink {
  const audiencePolicy = {
    allowLoopbackAudiences: prepared.allowLoopbackAudiences === true
  }
  validateDelegation(prepared.grant, audiencePolicy)
  if (hashDelegation(prepared.grant, audiencePolicy) !== prepared.digest) {
    throw new Erc8128Error("INVALID_OPTIONS", "Delegation digest changed.")
  }
  const bytes =
    signature instanceof Uint8Array ? signature : hexToBytes(signature)
  if (
    bytes.length === 0 ||
    bytes.length > maximumDelegationGrantSignatureBytes
  ) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Delegation signature has an unsupported size."
    )
  }
  const link = { grant: prepared.grant, signature: bytesToHex(bytes) }
  encodeDelegationLink(link, audiencePolicy)
  return link
}

export async function signDelegationGrant(
  args: SignDelegationGrantArgs
): Promise<DelegationLink> {
  const { signer, ...grantArgs } = args
  const expectedIssuer = formatKeyId(signer.chainId, signer.address)
  const prepared = buildDelegationGrant(grantArgs)
  if (prepared.grant.issuer !== expectedIssuer) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Delegation signer must match the issuer."
    )
  }
  return completeDelegationGrant(
    prepared,
    await signer.signTypedData(prepared.typedData)
  )
}

export function createDelegationChain(
  links: readonly DelegationLink[],
  audiencePolicy: DelegationAudiencePolicy = {}
): DelegationChain {
  const chain = { links: [...links] }
  return parseDelegationField(
    formatDelegationField(chain, audiencePolicy),
    audiencePolicy
  ).chain
}
