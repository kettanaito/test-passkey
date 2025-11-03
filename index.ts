import { generateKeyPairSync } from 'node:crypto'
import type { Protocol } from 'playwright-core/types/protocol'
import cbor from 'cbor'

type PlaywrightCredential = Protocol.WebAuthn.Credential

export interface TestPasskey {
  credential: TestPasskeyCredential
  publicKey: Uint8Array
}

export interface TestPasskeyCredential
  extends Pick<
    PlaywrightCredential,
    'credentialId' | 'rpId' | 'signCount' | 'privateKey'
  > {
  aaguid: string
}

export type CreateTestPasskeyOptions = Partial<TestPasskeyCredential>

export function createTestPasskey(
  options: CreateTestPasskeyOptions,
): TestPasskey {
  const { publicKey, privateKey } = generateKeys()

  return {
    credential: {
      /**
       * @note This has to be Base64-encoded because WebAuthn expects that encoding.
       * Store the same encoded value in the database so the keypass could be looked up by ID.
       */
      credentialId: options.credentialId || btoa(crypto.randomUUID()),
      rpId: options.rpId,
      aaguid:
        options.aaguid ??
        btoa(crypto.getRandomValues(new Uint8Array(16)).toString()),
      signCount: options.signCount || 0,
      privateKey,
    },
    publicKey,
  }
}

function generateKeys() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  })

  const spkiPublicKey = publicKey.export({ type: 'spki', format: 'der' })
  const publicKeyBytes = spkiPublicKey.subarray(-65)
  const x = publicKeyBytes.subarray(1, 33)
  const y = publicKeyBytes.subarray(33, 65)

  const cosePublickey = cbor.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, x],
      [-3, y],
    ]),
  )

  return {
    privateKey: privateKey
      .export({ type: 'pkcs8', format: 'der' })
      .toString('base64'),
    publicKey: cosePublickey,
  }
}
