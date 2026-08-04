import type {
  GetAccountCodeFn,
  VerifyDigestFn,
  VerifyMessageArgs,
  VerifyMessageFn,
  VerifySmartAccountFn
} from "../types"
import {
  hashEthereumMessage,
  verifyCanonicalEoaDigestSignature,
  verifyCanonicalEoaSignature
} from "./ecdsa"
import { bytesToHex, hexToBytes } from "./utilities"

const ERC_6492_MAGIC =
  "6492649264926492649264926492649264926492649264926492649264926492"

export const ERC1271_ABI = [
  {
    type: "function",
    name: "isValidSignature",
    stateMutability: "view",
    inputs: [
      { name: "hash", type: "bytes32" },
      { name: "signature", type: "bytes" }
    ],
    outputs: [{ name: "magicValue", type: "bytes4" }]
  }
] as const

export function createUniversalAccountVerifier(args: {
  getCode: GetAccountCodeFn
  verifySmartAccount: VerifySmartAccountFn
}): VerifyMessageFn {
  return async (input) => {
    if (isErc6492Signature(input.signature)) {
      return callSmartAccountVerifier(
        args.verifySmartAccount,
        input,
        "counterfactual"
      )
    }

    let code: Awaited<ReturnType<GetAccountCodeFn>>
    try {
      code = await args.getCode({
        address: input.address,
        chainId: input.chainId
      })
    } catch {
      return "unavailable"
    }
    if (code === "unavailable") return "unavailable"
    if (code !== undefined && code !== "0x") {
      return callSmartAccountVerifier(
        args.verifySmartAccount,
        input,
        "deployed"
      )
    }
    return verifyCanonicalEoaSignature({
      address: input.address,
      message: hexToBytes(input.message.raw),
      signature: input.signature
    })
  }
}

export function createUniversalAccountDigestVerifier(args: {
  getCode: GetAccountCodeFn
  verifySmartAccount: VerifySmartAccountFn
}): VerifyDigestFn {
  return async (input) => {
    const messageInput: VerifyMessageArgs = {
      address: input.address,
      chainId: input.chainId,
      message: { raw: input.digest },
      signature: input.signature
    }
    if (isErc6492Signature(input.signature)) {
      return callSmartAccountDigestVerifier(
        args.verifySmartAccount,
        messageInput,
        input.digest,
        "counterfactual"
      )
    }
    let code: Awaited<ReturnType<GetAccountCodeFn>>
    try {
      code = await args.getCode({
        address: input.address,
        chainId: input.chainId
      })
    } catch {
      return "unavailable"
    }
    if (code === "unavailable") return "unavailable"
    if (code !== undefined && code !== "0x") {
      return callSmartAccountDigestVerifier(
        args.verifySmartAccount,
        messageInput,
        input.digest,
        "deployed"
      )
    }
    return verifyCanonicalEoaDigestSignature(input)
  }
}

function isErc6492Signature(signature: string): boolean {
  return signature.toLowerCase().endsWith(ERC_6492_MAGIC)
}

async function callSmartAccountVerifier(
  verifyMessage: VerifySmartAccountFn,
  input: VerifyMessageArgs,
  accountType: "counterfactual" | "deployed"
): Promise<boolean | "unavailable"> {
  try {
    return await verifyMessage({
      ...input,
      accountType,
      digest: bytesToHex(hashEthereumMessage(hexToBytes(input.message.raw)))
    })
  } catch {
    return "unavailable"
  }
}

async function callSmartAccountDigestVerifier(
  verifyMessage: VerifySmartAccountFn,
  input: VerifyMessageArgs,
  digest: import("../types").Hex,
  accountType: "counterfactual" | "deployed"
): Promise<boolean | "unavailable"> {
  try {
    return await verifyMessage({ ...input, accountType, digest })
  } catch {
    return "unavailable"
  }
}
