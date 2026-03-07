import { parseKeyId, selectSignatureFromHeaders } from "@slicekit/erc8128"

export type PlaygroundSignatureMetadata = {
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

function includesAll(required: string[], components: string[]) {
  const covered = new Set(components)
  return required.every((component) => covered.has(component))
}

async function inferBinding(request: Request, components: string[]) {
  const url = new URL(request.url)
  const required = ["@authority", "@method", "@path"]

  if (url.search.length > 0) {
    required.push("@query")
  }

  const hasBody =
    request.method !== "GET" &&
    request.method !== "HEAD" &&
    (await request.clone().arrayBuffer()).byteLength > 0

  if (hasBody) {
    required.push("content-digest")
  }

  return includesAll(required, components) ? "request-bound" : "class-bound"
}

export async function parsePlaygroundSignature(
  request: Request
): Promise<PlaygroundSignatureMetadata | null> {
  const signatureInputHeader = request.headers.get("signature-input")
  const signatureHeader = request.headers.get("signature")

  if (!signatureInputHeader || !signatureHeader) {
    return null
  }

  const selected = selectSignatureFromHeaders({
    signatureInputHeader,
    signatureHeader,
    policy: { label: "eth", strictLabel: false }
  })

  if (!selected.ok || selected.selected.length === 0) {
    return null
  }

  const candidate = selected.selected[0]
  const parsedKeyId = parseKeyId(candidate.params.keyid)

  return {
    address: parsedKeyId?.address ?? "",
    chainId: parsedKeyId?.chainId ?? 1,
    label: candidate.label,
    components: candidate.components,
    binding: await inferBinding(request, candidate.components),
    replayable: !candidate.params.nonce,
    params: {
      created: candidate.params.created,
      expires: candidate.params.expires,
      keyid: candidate.params.keyid.toLowerCase(),
      ...(candidate.params.nonce ? { nonce: candidate.params.nonce } : {})
    }
  }
}
