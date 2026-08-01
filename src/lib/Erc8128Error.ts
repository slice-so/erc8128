export class Erc8128Error extends Error {
  constructor(
    public code:
      | "CRYPTO_UNAVAILABLE"
      | "INVALID_OPTIONS"
      | "UNSUPPORTED_REQUEST"
      | "BODY_READ_FAILED"
      | "DIGEST_REQUIRED"
      | "BAD_DERIVED_VALUE"
      | "BAD_HEADER_VALUE"
      | "DELEGATION_TOO_LARGE"
      | "PARSE_ERROR",
    message: string
  ) {
    super(message)
    this.name = "Erc8128Error"
  }
}

export class VerificationUnavailableError extends Error {
  constructor(message = "Account verification is unavailable.") {
    super(message)
    this.name = "VerificationUnavailableError"
  }
}
