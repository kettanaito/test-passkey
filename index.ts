import { generateKeyPairSync } from 'node:crypto'
import cbor from 'cbor'

export type TestPasskey = {
  credential: TestPasskeyCredential
  publicKey: Uint8Array<ArrayBuffer>
}

export type TestPasskeyCredential = {
  /**
   * Base64-encoded unique ID of the passkey.
   */
  credentialId: string
  rpId: string
  signCount: number
  /**
   * The ECDSA P-256 private key in PKCS#8 format.
   */
  privateKey: string
  aaguid?: string
}

export type CreateTestPasskeyOptions = {
  rpId: string
  credentialId?: string
  aaguid?: string
  signCount?: number
}

export function createTestPasskey(
  options: CreateTestPasskeyOptions,
): TestPasskey {
  const { publicKey, privateKey } = generateKeyPair()

  return {
    credential: {
      /**
       * @note This has to be Base64-encoded because WebAuthn expects that encoding.
       * Store the same encoded value in the database so the keypass could be looked up by ID.
       */
      credentialId: options.credentialId || btoa(crypto.randomUUID()),
      rpId: options.rpId,
      aaguid: options.aaguid,
      signCount: options.signCount || 0,
      privateKey,
    },
    publicKey,
  }
}

function generateKeyPair() {
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
    publicKey: cosePublickey as Uint8Array<ArrayBuffer>,
  }
}
