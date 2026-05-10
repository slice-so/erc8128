import type { BindingMode, ReplayMode } from "./signing"

export type AcceptSignatureRequestShape =
  | Request
  | {
      hasQuery: boolean
      hasBody: boolean
    }

export type AcceptSignatureSignOptions = {
  binding: BindingMode
  replay: ReplayMode
  components: string[]
}

export type ParsedAcceptSignatureMember = {
  label: string
  components: string[]
  requiredParams: string[]
  acceptSignatureValue: string
  signOptions?: AcceptSignatureSignOptions
}

export type SelectAcceptSignatureRetryOptionsArgs = {
  members: Pick<ParsedAcceptSignatureMember, "components" | "requiredParams">[]
  requestShape: AcceptSignatureRequestShape
  attemptedOptions?: Array<Partial<AcceptSignatureSignOptions> | undefined>
}
