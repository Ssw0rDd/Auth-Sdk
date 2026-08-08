import { describe, expect, it } from 'vitest'

import {
  createEncryptedBffStores,
  createRedisAtomicBlobStore,
  type AtomicBlobStore,
} from './stores'

class FakeBlobs implements AtomicBlobStore {
  readonly values = new Map<string, { value: string; expiresAt: number }>()

  async putIfAbsent(key: string, value: string, expiresAt: number): Promise<boolean> {
    if (this.values.has(key)) return false
    this.values.set(key, { value, expiresAt })
    return true
  }

  async set(key: string, value: string, expiresAt: number): Promise<void> {
    this.values.set(key, { value, expiresAt })
  }

  async get(key: string): Promise<string | null> {
    return this.values.get(key)?.value ?? null
  }

  async getAndDelete(key: string): Promise<string | null> {
    const value = this.values.get(key)?.value ?? null
    this.values.delete(key)
    return value
  }

  async delete(key: string): Promise<void> {
    this.values.delete(key)
  }

  async runExclusive<T>(_key: string, operation: () => Promise<T>): Promise<T> {
    return operation()
  }
}

describe('encrypted BFF stores', () => {
  it('seals bearer material with context-bound AES-256-GCM and preserves atomic take', async () => {
    const blobs = new FakeBlobs()
    const stores = createEncryptedBffStores({
      blobs,
      prefix: 'prod-auth',
      activeKeyId: 'k2',
      keys: { k2: new Uint8Array(32).fill(7) },
    })
    const state = 'state_0123456789abcdefghijklmnopqrstuvwxyzABCDE'
    await stores.transactions.put(state, {
      binding: 'binding_0123456789abcdefghijklmnopqrstuvwxyzAB',
      expiresAt: Date.now() + 60_000,
      provider: 'google',
      rememberMe: true,
      transaction: {
        state,
        nonce: 'nonce_0123456789abcdefghijklmnopqrstuvwxyzABCDE',
        pkceVerifier: 'verifier_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
      },
    })
    const storedText = [...blobs.values.values()][0]?.value ?? ''
    expect(storedText).not.toContain('verifier_')
    expect(storedText).not.toContain('binding_')
    await expect(stores.transactions.take(state)).resolves.toMatchObject({ provider: 'google' })
    await expect(stores.transactions.take(state)).resolves.toBeNull()
  })

  it('fails closed when ciphertext is tampered with or moved to another record key', async () => {
    const blobs = new FakeBlobs()
    const stores = createEncryptedBffStores({
      blobs,
      prefix: 'prod-auth',
      activeKeyId: 'k1',
      keys: { k1: new Uint8Array(32).fill(3) },
    })
    await stores.sessions.put('session-a', {
      backend: {
        accessToken: 'access-secret-value',
        refreshToken: 'refresh-secret-value',
        expiresAt: '2099-01-01T00:00:00Z',
      },
      expiresAt: Date.now() + 60_000,
    })
    const entry = [...blobs.values.entries()][0]
    if (!entry) throw new Error('missing encrypted record')
    blobs.values.set(entry[0].replace('session-a', 'session-b'), entry[1])
    await expect(stores.sessions.get('session-b')).rejects.toThrow(/decrypt/u)

    const envelope = JSON.parse(entry[1].value) as { ciphertext: string }
    envelope.ciphertext = `${envelope.ciphertext.startsWith('A') ? 'B' : 'A'}${envelope.ciphertext.slice(1)}`
    blobs.values.set(entry[0], { ...entry[1], value: JSON.stringify(envelope) })
    await expect(stores.sessions.get('session-a')).rejects.toThrow(/decrypt/u)
  })

  it('uses Redis NX/PXAT and GETDEL primitives instead of process-local locks', async () => {
    const commands: string[][] = []
    const redis = createRedisAtomicBlobStore({
      sendCommand: async (command) => {
        commands.push(command)
        if (command[0] === 'SET' && command.includes('NX')) return 'OK'
        if (command[0] === 'GETDEL') return 'sealed-value'
        if (command[0] === 'GET') return null
        return 1
      },
    })
    await expect(redis.putIfAbsent('key', 'sealed', 2_000_000_000_000)).resolves.toBe(true)
    await expect(redis.getAndDelete('key')).resolves.toBe('sealed-value')
    await expect(redis.runExclusive('session-key', async () => 'protected')).resolves.toBe(
      'protected',
    )
    expect(commands[0]).toEqual([
      'SET',
      'key',
      'sealed',
      'PXAT',
      '2000000000000',
      'NX',
    ])
    expect(commands[1]).toEqual(['GETDEL', 'key'])
    expect(commands[2]?.slice(0, 2)).toEqual(['SET', 'session-key:lease'])
    expect(commands[3]?.[0]).toBe('EVAL')
  })
})
