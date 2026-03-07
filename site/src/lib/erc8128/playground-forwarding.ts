const JSON_CONTENT_TYPE_RE = /^application\/([a-z0-9.+-]*\+)?json/i

export type PreparedVerifyRequest =
  | { ok: true; request: Request }
  | {
      ok: false
      error: "invalid_json"
      detail: "Request body is not valid JSON"
    }

export async function prepareVerifyRequest(
  request: Request,
  destinationUrl: URL
): Promise<PreparedVerifyRequest> {
  const headers = new Headers(request.headers)

  if (request.method === "GET" || request.method === "HEAD") {
    return {
      ok: true,
      request: new Request(destinationUrl.toString(), {
        method: request.method,
        headers
      })
    }
  }

  const contentType = headers.get("content-type") ?? ""

  if (JSON_CONTENT_TYPE_RE.test(contentType)) {
    const bodyText = await request.clone().text()

    if (bodyText.trim().length === 0) {
      headers.delete("content-type")
      headers.delete("content-length")

      return {
        ok: true,
        request: new Request(destinationUrl.toString(), {
          method: request.method,
          headers
        })
      }
    }

    try {
      JSON.parse(bodyText)
    } catch {
      return {
        ok: false,
        error: "invalid_json",
        detail: "Request body is not valid JSON"
      }
    }
  }

  return {
    ok: true,
    request: new Request(destinationUrl.toString(), {
      method: request.method,
      headers,
      body: request.body ?? undefined
    })
  }
}
