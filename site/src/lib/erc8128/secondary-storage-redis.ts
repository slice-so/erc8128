import { connect } from "cloudflare:sockets"
import { date } from "@slicekit/better-auth"

type RedisValue = string | number | null | RedisValue[]

export interface SecondaryStorage {
  get(key: string): Promise<string | null>
  set(key: string, value: string, ttlSec?: number): Promise<void>
  delete(key: string): Promise<void>
  setIfNotExists?(key: string, value: string, ttlSec?: number): Promise<boolean>
}

export interface RequestScopedSecondaryStorage extends SecondaryStorage {
  close(): Promise<void>
}

export interface RedisSecondaryStorageOptions {
  connectionString: string
  keyPrefix?: string
}

type RedisConnectionInfo = {
  hostname: string
  port: number
  secure: boolean
  username?: string
  password?: string
  database?: number
}

interface RedisConnection {
  writer: WritableStreamDefaultWriter<Uint8Array>
  reader: RespReader
  close: () => Promise<void>
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

class RespReader {
  private buffer = new Uint8Array(0)

  constructor(
    private readonly reader: ReadableStreamDefaultReader<Uint8Array>
  ) {}

  private async fill(minBytes: number) {
    while (this.buffer.length < minBytes) {
      const { done, value } = await this.reader.read()
      if (done || !value) {
        throw new Error("Unexpected end of Redis response")
      }

      const merged = new Uint8Array(this.buffer.length + value.length)
      merged.set(this.buffer)
      merged.set(value, this.buffer.length)
      this.buffer = merged
    }
  }

  private async readBytes(length: number) {
    await this.fill(length)
    const chunk = this.buffer.slice(0, length)
    this.buffer = this.buffer.slice(length)
    return chunk
  }

  private async readLine() {
    while (true) {
      for (let index = 0; index < this.buffer.length - 1; index += 1) {
        if (this.buffer[index] === 13 && this.buffer[index + 1] === 10) {
          const line = this.buffer.slice(0, index)
          this.buffer = this.buffer.slice(index + 2)
          return decoder.decode(line)
        }
      }

      const { done, value } = await this.reader.read()
      if (done || !value) {
        throw new Error("Unexpected end of Redis response")
      }

      const merged = new Uint8Array(this.buffer.length + value.length)
      merged.set(this.buffer)
      merged.set(value, this.buffer.length)
      this.buffer = merged
    }
  }

  async readValue(): Promise<RedisValue> {
    const prefix = decoder.decode(await this.readBytes(1))

    if (prefix === "+") {
      return this.readLine()
    }

    if (prefix === "-") {
      throw new Error(await this.readLine())
    }

    if (prefix === ":") {
      return Number(await this.readLine())
    }

    if (prefix === "$") {
      const length = Number(await this.readLine())
      if (length < 0) {
        return null
      }

      const value = await this.readBytes(length)
      await this.readBytes(2)
      return decoder.decode(value)
    }

    if (prefix === "*") {
      const length = Number(await this.readLine())
      if (length < 0) {
        return null
      }

      const values: RedisValue[] = []
      for (let index = 0; index < length; index += 1) {
        values.push(await this.readValue())
      }
      return values
    }

    throw new Error(`Unsupported Redis response prefix: ${prefix}`)
  }
}

function parseRedisUrl(connectionString: string): RedisConnectionInfo {
  const url = new URL(connectionString)

  if (url.protocol !== "redis:" && url.protocol !== "rediss:") {
    throw new Error(
      `[erc8128/site] REDIS_URL must use redis:// or rediss://, received ${url.protocol}`
    )
  }

  const port =
    url.port.length > 0
      ? Number(url.port)
      : url.protocol === "rediss:"
        ? 6380
        : 6379

  const database =
    url.pathname.length > 1 ? Number(url.pathname.slice(1)) : undefined

  return {
    hostname: url.hostname,
    port,
    secure: url.protocol === "rediss:",
    username: url.username ? decodeURIComponent(url.username) : undefined,
    password: url.password ? decodeURIComponent(url.password) : undefined,
    database:
      database != null && Number.isFinite(database) ? database : undefined
  }
}

function encodeCommand(parts: string[]) {
  const serialized = [
    `*${parts.length}\r\n`,
    ...parts.map((part) => {
      const value = encoder.encode(part)
      return `$${value.length}\r\n${part}\r\n`
    })
  ].join("")

  return encoder.encode(serialized)
}

async function openConnection(
  config: RedisConnectionInfo
): Promise<RedisConnection> {
  const socket = connect(
    {
      hostname: config.hostname,
      port: config.port
    },
    {
      secureTransport: config.secure ? "on" : "off",
      allowHalfOpen: false
    }
  )

  const writer = socket.writable.getWriter()
  const rawReader = socket.readable.getReader()
  const reader = new RespReader(rawReader)

  if (config.password) {
    const authCommand = config.username
      ? ["AUTH", config.username, config.password]
      : ["AUTH", config.password]
    await writer.write(encodeCommand(authCommand))
    await reader.readValue()
  }

  if (config.database != null && config.database !== 0) {
    await writer.write(encodeCommand(["SELECT", String(config.database)]))
    await reader.readValue()
  }

  return {
    writer,
    reader,
    close: async () => {
      rawReader.releaseLock()
      writer.releaseLock()
      await socket.close().catch(() => undefined)
    }
  }
}

export function createRedisSecondaryStorage(
  options: string | RedisSecondaryStorageOptions
): RequestScopedSecondaryStorage {
  const { connectionString, keyPrefix = "better-auth:" } =
    typeof options === "string"
      ? { connectionString: options, keyPrefix: "better-auth:" }
      : options

  const config = parseRedisUrl(connectionString)
  const prefixKey = (key: string) => `${keyPrefix}${key}`
  let connection: RedisConnection | null = null
  let pending = Promise.resolve()

  async function getOrCreateConnection(): Promise<RedisConnection> {
    if (connection) {
      return connection
    }

    connection = await openConnection(config)
    return connection
  }

  async function execute(command: string[]) {
    try {
      const conn = await getOrCreateConnection()
      await conn.writer.write(encodeCommand(command))
      return await conn.reader.readValue()
    } catch (err) {
      if (connection) {
        await connection.close().catch(() => undefined)
        connection = null
        const freshConnection = await openConnection(config)
        connection = freshConnection
        await freshConnection.writer.write(encodeCommand(command))
        return await freshConnection.reader.readValue()
      }
      throw err
    }
  }

  function runSerialized<T>(fn: () => Promise<T>): Promise<T> {
    const operation = pending.then(fn, fn)
    pending = operation.then(
      () => undefined,
      () => undefined
    )
    return operation
  }

  return {
    async get(key) {
      const value = await runSerialized(() => execute(["GET", prefixKey(key)]))
      console.log("get", prefixKey(key), value)
      return typeof value === "string" ? value : null
    },

    async set(key, value, ttlSec) {
      await runSerialized(async () => {
        console.log("set init", Date.now())

        if (ttlSec != null) {
          await execute([
            "SET",
            prefixKey(key),
            value,
            "EX",
            String(Math.max(1, ttlSec))
          ])
          return
        }

        await execute(["SET", prefixKey(key), value])
      })
    },

    async delete(key) {
      await runSerialized(() => execute(["DEL", prefixKey(key)]))
    },

    async setIfNotExists(key, value, ttlSec) {
      return runSerialized(async () => {
        console.log("setIfNotExists init", Date.now())

        const command = ["SET", prefixKey(key), value, "NX"]
        if (ttlSec != null) {
          command.push("EX", String(Math.max(1, ttlSec)))
        }

        const result = await execute(command)
        console.log("setIfNotExists end", Date.now())
        return result === "OK"
      })
    },

    async close() {
      console.log("close init", Date.now())
      await pending
      if (!connection) {
        return
      }

      const currentConnection = connection
      connection = null
      await currentConnection.close().catch(() => undefined)
    }
  }
}
