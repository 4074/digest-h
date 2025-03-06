import crypto from 'crypto'

export const md5 = (s: string) => crypto.createHash('md5').update(s).digest('hex')

export interface CreateDigestOptions {}

export interface CreateDigestSource {
  realm: string
  username: string
  password: string
  method: 'GET' | 'POST'
  uri: string
  nonce?: string
  cnonce?: string
  qop?: string
  nc?: number
  opaque?: string
}

const createCNonce = () => Date.now().toString()

export const createDigest = ({
  realm,
  username,
  password,
  method,
  uri,
  nonce,
  cnonce = createCNonce(),
  nc,
  qop = 'auth',
  opaque
}: CreateDigestSource) => {
  const ha1 = md5([username, password].join(':'))
  const ha2 = md5([method, uri].join(':'))
  const response = md5([ha1, nonce, nc, cnonce, qop, ha2].filter(Boolean).join(':'))
  const keys = ['username', 'realm', 'nonce', 'uri', 'qop', 'nc', 'cnonce', 'response', 'opaque']
  const values = {
    username,
    realm,
    nonce,
    uri,
    qop,
    nc,
    cnonce,
    response,
    opaque
  }

  const digest = `Digest ${keys
    .filter((k) => values[k])
    .map((k) => {
      const v = typeof values[k] === 'number' ? values[k].toString() : `"${values[k]}"`
      return `${k}=${v}`
    })}`

  return digest
}
