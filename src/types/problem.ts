import type { VerifyFailReason } from "./verifying"

export type Erc8128ProblemDetails = {
  type: string
  title: string
  status: 401 | 503
  detail?: string
  reason: VerifyFailReason
}
