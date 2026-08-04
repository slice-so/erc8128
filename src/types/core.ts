export type Hex = `0x${string}`
export type Address = `0x${string}`

export type ComponentIdentifier = {
  name: string
  params?: {
    sf?: true
    bs?: true
    tr?: true
    req?: true
    key?: string
    name?: string
  }
}

export type CoveredComponent = string | ComponentIdentifier

export type SfToken = { type: "token"; value: string }
export type SfByteSequence = { type: "binary"; value: Uint8Array }
export type SfDecimal = { type: "decimal"; value: number }
export type SfBareItem =
  | string
  | number
  | boolean
  | SfToken
  | SfByteSequence
  | SfDecimal
export type SfParameters = Record<string, SfBareItem | true>
export type SfItem = { value: SfBareItem; params?: SfParameters }
export type SfInnerList = { items: SfItem[]; params?: SfParameters }
export type SfMember = SfItem | SfInnerList
export type SfDictionary = Record<string, SfMember>
