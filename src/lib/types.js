//////////////////////////////
// Types
//////////////////////////////
export class Erc8128Error extends Error {
  code
  constructor(code, message) {
    super(message)
    this.code = code
    this.name = "Erc8128Error"
  }
}
//# sourceMappingURL=types.js.map
