import crypto from 'crypto'

export const md5 = (s: string) => crypto.createHash('md5').update(s).digest('hex')

export interface DigestParts {
  realm: string
  username: string
  password: string
  uri: string
  nonce?: string
  cnonce?: string
  qop?: string
  nc?: number
  opaque?: string
}

export interface CreateDigestSource extends DigestParts {
  method: string
}

const createCnonce = () => Date.now().toString()

export const createDigest = ({
  realm,
  username,
  password,
  method,
  uri,
  nonce,
  cnonce = createCnonce(),
  nc,
  qop = 'auth',
  opaque
}: CreateDigestSource) => {
  const ha1 = md5([username, password].join(':'))
  const ha2 = md5([method.toUpperCase(), uri].join(':'))
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
    })
    .join(', ')}`

  return digest
}

const PART_RE = `(\\w+)=["']?([^'"]{1,10000})["']?`
const getParts = (s: string) => {
  const pairs = s.match(new RegExp(PART_RE, 'g'))
  const parts = {}
  for (const pair of pairs) {
    const [, k, v] = pair.match(new RegExp(PART_RE))
    parts[k] = v
  }
  return parts as DigestParts & { response: string }
}

export interface ValidDigestSource {
  method: string
  digest: string
  password: string
}

export interface ValidDigestOptions {
  isCnonceDate?: boolean
  expried?: number
  needs?: (keyof DigestParts)[]
}

export const validDigest = ({ method, digest, password }: ValidDigestSource, options: ValidDigestOptions = {}) => {
  const { expried = 60, isCnonceDate = true, needs = ['username', 'realm', 'uri', 'qop', 'cnonce'] } = options
  const parts = getParts(digest)
  if (!needs.reduce((r, k) => r && Boolean(parts[k]), true)) {
    return false
  }
  if (isCnonceDate && Date.now() - Number(parts.cnonce) > expried * 1000) {
    return false
  }
  const localParts = getParts(
    createDigest({
      ...parts,
      method,
      password
    })
  )
  return parts.response === localParts.response
}
