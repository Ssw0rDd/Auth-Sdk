import type {
  BrowserSessionStore,
  OAuthTransactionStore,
  PendingFlowStore,
  StoredBrowserSession,
  StoredOAuthTransaction,
  StoredPendingFlow,
} from './index'

/**
 * Minimal distributed-store port. `putIfAbsent` and `getAndDelete` must be
 * atomic across all processes; implementations should also enforce expiresAt.
 */
export interface AtomicBlobStore {
  putIfAbsent(key: string, value: string, expiresAt: number): Promise<boolean>
  set(key: string, value: string, expiresAt: number): Promise<void>
  get(key: string): Promise<string | null>
  getAndDelete(key: string): Promise<string | null>
  delete(key: string): Promise<void>
  runExclusive<T>(key: string, operation: () => Promise<T>): Promise<T>
}

export interface EncryptedBffStoresOptions {
  blobs: AtomicBlobStore
  /** Deployment-specific namespace; changing it cryptographically separates records. */
  prefix: string
  activeKeyId: string
  /** Active and retained 32-byte AES-256 keys, normally loaded from KMS/secret storage. */
  keys: Readonly<Record<string, Uint8Array>>
}

export interface EncryptedBffStores {
  transactions: OAuthTransactionStore
  sessions: BrowserSessionStore
  pendingFlows: PendingFlowStore
}

export interface RedisCommandClient {
  sendCommand(command: string[]): Promise<unknown>
}

/** Redis 7/8 adapter using server-side atomic primitives and absolute TTLs. */
export function createRedisAtomicBlobStore(client: RedisCommandClient): AtomicBlobStore {
  return {
    async putIfAbsent(key, value, expiresAt) {
      const result = await client.sendCommand([
        'SET',
        key,
        value,
        'PXAT',
        String(expiresAt),
        'NX',
      ])
      if (result === 'OK') return true
      if (result === null) return false
      throw new Error('invalid Redis SET NX response')
    },
    async set(key, value, expiresAt) {
      const result = await client.sendCommand(['SET', key, value, 'PXAT', String(expiresAt)])
      if (result !== 'OK') throw new Error('invalid Redis SET response')
    },
    async get(key) {
      return redisOptionalString(await client.sendCommand(['GET', key]))
    },
    async getAndDelete(key) {
      return redisOptionalString(await client.sendCommand(['GETDEL', key]))
    },
    async delete(key) {
      const result = await client.sendCommand(['DEL', key])
      if (typeof result !== 'number' && typeof result !== 'bigint') {
        throw new Error('invalid Redis DEL response')
      }
    },
    async runExclusive<T>(key: string, operation: () => Promise<T>): Promise<T> {
      const leaseKey = `${key}:lease`
      const owner = randomOwner()
      let acquired = false
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const result = await client.sendCommand([
          'SET',
          leaseKey,
          owner,
          'PX',
          '30000',
          'NX',
        ])
        if (result === 'OK') {
          acquired = true
          break
        }
        if (result !== null) throw new Error('invalid Redis lease response')
        await delay(10)
      }
      if (!acquired) throw new Error('session lease unavailable')
      try {
        return await operation()
      } finally {
        const released = await client.sendCommand([
          'EVAL',
          "if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end",
          '1',
          leaseKey,
          owner,
        ])
        if (released !== 1 && released !== 1n) throw new Error('session lease expired')
      }
    },
  }
}

interface Envelope {
  version: 1
  keyId: string
  iv: string
  ciphertext: string
}

const IDENTIFIER = /^[A-Za-z0-9_-]{1,128}$/u

/**
 * Creates AEAD-sealed stores. AES-GCM authenticates the deployment prefix,
 * record type, record key and envelope version as associated data.
 */
export function createEncryptedBffStores(options: EncryptedBffStoresOptions): EncryptedBffStores {
  if (!IDENTIFIER.test(options.prefix) || !IDENTIFIER.test(options.activeKeyId)) {
    throw new Error('invalid encrypted store identifier')
  }
  const rawKeys = new Map<string, Uint8Array>()
  for (const [keyId, material] of Object.entries(options.keys)) {
    if (!IDENTIFIER.test(keyId) || material.byteLength !== 32) {
      throw new Error('invalid encrypted store key')
    }
    rawKeys.set(keyId, Uint8Array.from(material))
  }
  if (!rawKeys.has(options.activeKeyId)) throw new Error('active encrypted store key is missing')
  const vault = new AesGcmVault(options.prefix, options.activeKeyId, rawKeys)

  const transactions = new EncryptedCollection<StoredOAuthTransaction>(
    options.blobs,
    vault,
    'oauth',
  )
  const sessions = new EncryptedCollection<StoredBrowserSession>(options.blobs, vault, 'session')
  const pending = new EncryptedCollection<StoredPendingFlow>(options.blobs, vault, 'pending')

  return {
    transactions: {
      async put(state, value) {
        if (!(await transactions.putIfAbsent(state, value))) throw new Error('OAuth state collision')
      },
      take: (state) => transactions.take(state),
    },
    sessions: {
      put: (id, value) => sessions.set(id, value),
      get: (id) => sessions.get(id),
      delete: (id) => sessions.delete(id),
      runExclusive: (id, operation) => sessions.runExclusive(id, operation),
    },
    pendingFlows: {
      async put(id, value) {
        if (!(await pending.putIfAbsent(id, value))) throw new Error('pending flow collision')
      },
      get: (id) => pending.get(id),
      delete: (id) => pending.delete(id),
    },
  }
}

class EncryptedCollection<T extends { expiresAt: number }> {
  readonly #blobs: AtomicBlobStore
  readonly #vault: AesGcmVault
  readonly #kind: string

  constructor(blobs: AtomicBlobStore, vault: AesGcmVault, kind: string) {
    this.#blobs = blobs
    this.#vault = vault
    this.#kind = kind
  }

  async putIfAbsent(id: string, value: T): Promise<boolean> {
    validateRecord(id, value.expiresAt)
    return this.#blobs.putIfAbsent(
      this.#key(id),
      await this.#vault.seal(this.#kind, id, value),
      value.expiresAt,
    )
  }

  async set(id: string, value: T): Promise<void> {
    validateRecord(id, value.expiresAt)
    await this.#blobs.set(
      this.#key(id),
      await this.#vault.seal(this.#kind, id, value),
      value.expiresAt,
    )
  }

  async get(id: string): Promise<T | null> {
    validateRecordId(id)
    const sealed = await this.#blobs.get(this.#key(id))
    if (sealed === null) return null
    const value = await this.#vault.open<T>(this.#kind, id, sealed)
    if (!validExpiry(value)) {
      await this.#blobs.delete(this.#key(id))
      return null
    }
    return value
  }

  async take(id: string): Promise<T | null> {
    validateRecordId(id)
    const sealed = await this.#blobs.getAndDelete(this.#key(id))
    if (sealed === null) return null
    const value = await this.#vault.open<T>(this.#kind, id, sealed)
    return validExpiry(value) ? value : null
  }

  delete(id: string): Promise<void> {
    validateRecordId(id)
    return this.#blobs.delete(this.#key(id))
  }

  runExclusive<R>(id: string, operation: () => Promise<R>): Promise<R> {
    validateRecordId(id)
    return this.#blobs.runExclusive(this.#key(id), operation)
  }

  #key(id: string): string {
    return this.#vault.storageKey(this.#kind, id)
  }
}

class AesGcmVault {
  readonly #prefix: string
  readonly #activeKeyId: string
  readonly #keys = new Map<string, Promise<CryptoKey>>()

  constructor(prefix: string, activeKeyId: string, keys: ReadonlyMap<string, Uint8Array>) {
    this.#prefix = prefix
    this.#activeKeyId = activeKeyId
    for (const [keyId, material] of keys) {
      this.#keys.set(
        keyId,
        crypto.subtle.importKey('raw', ownedBuffer(material), { name: 'AES-GCM' }, false, [
          'encrypt',
          'decrypt',
        ]),
      )
    }
  }

  storageKey(kind: string, id: string): string {
    return `${this.#prefix}:${kind}:${id}`
  }

  async seal(kind: string, id: string, value: unknown): Promise<string> {
    const key = await this.#requiredKey(this.#activeKeyId)
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode(JSON.stringify(value))
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ownedBuffer(iv),
        additionalData: ownedBuffer(this.#aad(kind, id)),
      },
      key,
      ownedBuffer(plaintext),
    )
    const envelope: Envelope = {
      version: 1,
      keyId: this.#activeKeyId,
      iv: base64Url(iv),
      ciphertext: base64Url(new Uint8Array(ciphertext)),
    }
    return JSON.stringify(envelope)
  }

  async open<T>(kind: string, id: string, sealed: string): Promise<T> {
    try {
      const parsed: unknown = JSON.parse(sealed)
      if (!isEnvelope(parsed)) throw new Error('invalid envelope')
      const key = await this.#requiredKey(parsed.keyId)
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ownedBuffer(fromBase64Url(parsed.iv)),
          additionalData: ownedBuffer(this.#aad(kind, id)),
        },
        key,
        ownedBuffer(fromBase64Url(parsed.ciphertext)),
      )
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)) as T
    } catch {
      throw new Error('encrypted store decrypt failed')
    }
  }

  #aad(kind: string, id: string): Uint8Array {
    return new TextEncoder().encode(`${this.#prefix}:${kind}:${id}:v1`)
  }

  async #requiredKey(keyId: string): Promise<CryptoKey> {
    const key = this.#keys.get(keyId)
    if (key === undefined) throw new Error('encrypted store key unavailable')
    return key
  }
}

function validateRecord(id: string, expiresAt: number): void {
  validateRecordId(id)
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) {
    throw new Error('invalid encrypted store expiry')
  }
}

function validateRecordId(id: string): void {
  if (!/^[A-Za-z0-9_-]{1,512}$/u.test(id)) throw new Error('invalid encrypted store record id')
}

function validExpiry(value: unknown): value is { expiresAt: number } {
  return (
    value !== null &&
    typeof value === 'object' &&
    Number.isSafeInteger((value as { expiresAt?: unknown }).expiresAt) &&
    Number((value as { expiresAt: number }).expiresAt) > Date.now()
  )
}

function isEnvelope(value: unknown): value is Envelope {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const envelope = value as Partial<Envelope>
  return (
    envelope.version === 1 &&
    typeof envelope.keyId === 'string' &&
    IDENTIFIER.test(envelope.keyId) &&
    typeof envelope.iv === 'string' &&
    typeof envelope.ciphertext === 'string'
  )
}

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length > 1_000_000) throw new Error('invalid base64')
  const padding = '='.repeat((4 - (value.length % 4)) % 4)
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  const result = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(result).set(bytes)
  return result
}

function redisOptionalString(value: unknown): string | null {
  if (value === null || typeof value === 'string') return value
  if (value instanceof Uint8Array) return new TextDecoder('utf-8', { fatal: true }).decode(value)
  throw new Error('invalid Redis string response')
}

function randomOwner(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return base64Url(bytes)
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}
