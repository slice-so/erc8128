import { Erc8128Error } from "./Erc8128Error"

export const invokeFetch = (
  fetchImplementation: typeof fetch | undefined,
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> => {
  const resolvedFetch = fetchImplementation ?? globalThis.fetch
  if (typeof resolvedFetch !== "function") {
    throw new Erc8128Error(
      "UNSUPPORTED_REQUEST",
      "No fetch implementation available."
    )
  }
  return resolvedFetch === globalThis.fetch
    ? globalThis.fetch(input, init)
    : resolvedFetch(input, init)
}
