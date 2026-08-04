import type {
  Delegation,
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
  formatDelegationField,
  getDelegationTypedData,
  hashDelegation,
  parseDelegationField,
  serializeDelegationComponent,
  validateDelegation,
  ZERO_DELEGATION_PARENT
} from "./delegationField"

export const maximumDelegationGrantSignatureBytes = 8_192

export function buildDelegationGrant(
  args: DelegationGrantBuildArgs
): PreparedDelegationGrant {
  const id =
    args.id instanceof Uint8Array ? bytesToHex(args.id) : args.id.toLowerCase()
  const grant: Delegation = {
    root: formatKeyId(args.root.chainId, args.root.address),
    delegate: formatKeyId(args.delegate.chainId, args.delegate.address),
    aud: [...args.audiences],
    id: id as Hex,
    epoch: args.epoch,
    created: args.created ?? unixNow(),
    expires: args.expires,
    maxAge: args.maxAge,
    delegateIsEOA: args.delegateIsEOA,
    allowReplayable: args.allowReplayable,
    components: (args.components ?? []).map((component) =>
      serializeDelegationComponent(normalizeComponentIdentifier(component))
    ),
    scope: [...(args.scopes ?? [])],
    parent: args.parent ?? ZERO_DELEGATION_PARENT
  }
  validateDelegation(grant)
  const typedData = getDelegationTypedData(grant)
  return { grant, digest: hashDelegation(grant), typedData }
}

export function completeDelegationGrant(
  prepared: PreparedDelegationGrant,
  signature: Hex | Uint8Array
): DelegationLink {
  validateDelegation(prepared.grant)
  if (hashDelegation(prepared.grant) !== prepared.digest) {
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
  return { grant: prepared.grant, signature: bytesToHex(bytes) }
}

export async function signDelegationGrant(
  args: SignDelegationGrantArgs
): Promise<DelegationLink> {
  const { signer, ...grantArgs } = args
  const expectedRoot = formatKeyId(signer.chainId, signer.address)
  const prepared = buildDelegationGrant(grantArgs)
  if (prepared.grant.root !== expectedRoot) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Delegation signer must match the Root Account."
    )
  }
  return completeDelegationGrant(
    prepared,
    await signer.signTypedData(prepared.typedData)
  )
}

export function createDelegationChain(
  links: readonly DelegationLink[]
): DelegationChain {
  const chain = { links: [...links] }
  return parseDelegationField(formatDelegationField(chain)).chain
}
