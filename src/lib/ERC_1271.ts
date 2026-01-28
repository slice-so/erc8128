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

export const ERC1271_MAGIC = "0x1626ba7e" as const
