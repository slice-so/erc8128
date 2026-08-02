import type {
  DelegationGrant,
  DelegationGrantBuildArgs,
  Hex,
  PreparedDelegationGrant,
  SignatureParams,
  SignDelegationGrantArgs
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { createSignatureBaseMinimal } from "../engine/createSignatureBase"
import { parseSignatureInputHeader } from "../engine/createSignatureInput"
import { serializeSignatureParamsInnerList } from "../engine/serializations"
import { formatKeyId } from "../keyId"
import { base64Decode, base64Encode, hexToBytes, unixNow } from "../utilities"
import {
  DELEGATION_COMPONENT,
  DELEGATION_FIELD_NAME,
  formatDelegationField,
  parseDelegationField,
  TAG_DELEGATION
} from "./delegationField"

export const maximumDelegationGrantSignatureBytes = 4_096

export function buildDelegationGrant(
  args: DelegationGrantBuildArgs
): PreparedDelegationGrant {
  const created = args.created ?? unixNow()
  if (!Number.isSafeInteger(created) || !Number.isSafeInteger(args.expires)) {
    throw new Erc8128Error("INVALID_OPTIONS", "Grant times must be integers.")
  }
  if (args.expires <= created) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Grant expires must be after created."
    )
  }
  const fieldValue = formatDelegationField(args)
  const params: PreparedDelegationGrant["params"] = {
    created,
    expires: args.expires,
    keyid: formatKeyId(args.root.chainId, args.root.address),
    tag: TAG_DELEGATION
  }
  const signatureParamsValue = serializeSignatureParamsInnerList(
    [DELEGATION_COMPONENT],
    params as SignatureParams
  )
  const request = new Request("https://erc8128.invalid/", {
    headers: { [DELEGATION_FIELD_NAME]: fieldValue }
  })
  const signatureBase = createSignatureBaseMinimal({
    request,
    components: [DELEGATION_COMPONENT],
    signatureParamsValue
  })
  return { fieldValue, signatureBase, signatureParamsValue, params }
}

export function completeDelegationGrant(
  prepared: PreparedDelegationGrant,
  signature: Hex | Uint8Array
): DelegationGrant {
  const signatureBytes =
    signature instanceof Uint8Array ? signature : hexToBytes(signature)
  if (
    signatureBytes.length === 0 ||
    signatureBytes.length > maximumDelegationGrantSignatureBytes
  ) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Grant signature has an unsupported size."
    )
  }
  return {
    fieldValue: prepared.fieldValue,
    grantSignatureInput: prepared.signatureParamsValue,
    grantSignatureB64: base64Encode(signatureBytes)
  }
}

export async function signDelegationGrant(
  args: SignDelegationGrantArgs
): Promise<DelegationGrant> {
  const { signer, ...grantArgs } = args
  if (
    signer.chainId !== grantArgs.root.chainId ||
    signer.address.toLowerCase() !== grantArgs.root.address.toLowerCase()
  ) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Grant signer must match the root account."
    )
  }
  const prepared = buildDelegationGrant(grantArgs)
  return completeDelegationGrant(
    prepared,
    await signer.signMessage(prepared.signatureBase)
  )
}

export function validateDelegationGrantArtifact(grant: DelegationGrant): void {
  if (
    grant.fieldValue.length === 0 ||
    grant.grantSignatureInput.length === 0 ||
    grant.grantSignatureB64.length === 0 ||
    base64Decode(grant.grantSignatureB64) === null
  ) {
    throw new Erc8128Error("PARSE_ERROR", "Invalid DelegationGrant artifact.")
  }
}

export function getDelegationGrantSignatureBase(
  grant: DelegationGrant
): Uint8Array {
  validateDelegationGrantArtifact(grant)
  const field = parseDelegationField(grant.fieldValue)
  const [input] = parseSignatureInputHeader(
    `grant=${grant.grantSignatureInput}`
  )
  if (
    input === undefined ||
    input.params.tag !== TAG_DELEGATION ||
    input.params.nonce !== undefined ||
    input.components.length !== 1 ||
    input.components[0]?.name !== DELEGATION_FIELD_NAME ||
    input.components[0]?.params?.sf !== true ||
    input.params.keyid !== formatKeyId(field.root.chainId, field.root.address)
  ) {
    throw new Erc8128Error(
      "PARSE_ERROR",
      "DelegationGrant signature input is invalid."
    )
  }
  return createSignatureBaseMinimal({
    request: new Request("https://erc8128.invalid/", {
      headers: { [DELEGATION_FIELD_NAME]: field.fieldValue }
    }),
    components: input.components,
    signatureParamsValue: input.signatureParamsValue
  })
}
