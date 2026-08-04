import type {
  Erc8128ProblemDetails,
  VerifyFailReason,
  VerifyResult
} from "../types"
import { Erc8128Error } from "./Erc8128Error"

const UNAVAILABLE_REASONS = new Set<VerifyFailReason>([
  "signature_verification_unavailable",
  "grant_verification_unavailable",
  "revocation_unavailable"
])
const BAD_REQUEST_REASONS = new Set<VerifyFailReason>([
  "signature_input_invalid",
  "signature_too_large",
  "delegation_too_large",
  "delegation_chain_too_long"
])

const VERIFY_FAILURE_REASONS = new Set<VerifyFailReason>([
  "signature_missing",
  "no_acceptable_signature",
  "signature_input_invalid",
  "signature_too_large",
  "invalid_keyid",
  "invalid_time",
  "request_not_yet_valid",
  "request_expired",
  "request_validity_too_long",
  "invalid_nonce",
  "insufficient_coverage",
  "content_digest_required",
  "bad_content_digest",
  "nonce_required",
  "nonce_reused",
  "replayable_not_allowed",
  "unsupported_algorithm",
  "bad_signature",
  "signature_verification_unavailable",
  "principal_not_allowed",
  "unsupported_delegation",
  "bad_delegation_field",
  "delegation_too_large",
  "delegation_not_covered",
  "delegate_mismatch",
  "delegation_chain_too_long",
  "delegation_chain_discontinuous",
  "delegation_attenuation_violation",
  "grant_expired",
  "grant_not_yet_valid",
  "grant_validity_too_long",
  "request_outside_grant_window",
  "bad_grant_signature",
  "audience_mismatch",
  "delegation_nonce_required",
  "delegation_max_age_exceeded",
  "delegation_components_unsupported",
  "delegation_components_uncovered",
  "unsupported_scope",
  "insufficient_scope",
  "grant_verification_unavailable",
  "authorization_revoked",
  "authorization_epoch_mismatch",
  "revocation_unavailable"
])

export function formatEthHttpSigChallenge(reason: VerifyFailReason): string {
  return `eth-http-sig error="${reason}"`
}

export function formatErc8128ProblemDetails(
  failure: Extract<VerifyResult, { ok: false }>
): Erc8128ProblemDetails {
  const status = UNAVAILABLE_REASONS.has(failure.reason)
    ? 503
    : BAD_REQUEST_REASONS.has(failure.reason)
      ? 400
      : failure.reason === "insufficient_scope"
        ? 403
        : 401
  return {
    type: `https://erc8128.org/problems/${failure.reason}`,
    title:
      status === 503
        ? "Authentication verification is temporarily unavailable"
        : status === 403
          ? "Authenticated authority is insufficient"
          : "Ethereum HTTP authentication failed",
    status,
    ...(failure.detail === undefined ? {} : { detail: failure.detail }),
    reason: failure.reason
  }
}

export function parseErc8128ProblemDetails(
  value: string
): Erc8128ProblemDetails {
  let parsed: Erc8128ProblemDetails
  try {
    parsed = JSON.parse(value) as Erc8128ProblemDetails
  } catch {
    throw new Erc8128Error("PARSE_ERROR", "Invalid problem details JSON.")
  }
  if (
    typeof parsed.type !== "string" ||
    typeof parsed.title !== "string" ||
    ![400, 401, 403, 503].includes(parsed.status) ||
    typeof parsed.reason !== "string" ||
    !VERIFY_FAILURE_REASONS.has(parsed.reason) ||
    (parsed.detail !== undefined && typeof parsed.detail !== "string")
  ) {
    throw new Erc8128Error("PARSE_ERROR", "Invalid ERC-8128 problem details.")
  }
  return parsed
}
