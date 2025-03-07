import { createDigest, validDigest } from '../src'

describe('createDigest', () => {
  it('should pass by mini options', () => {
    expect(
      createDigest({
        realm: 'digest-h',
        username: 'user',
        password: '123456',
        method: 'GET',
        uri: '/index',
        cnonce: '1741284305531'
      })
    ).toEqual(
      'Digest username="user", realm="digest-h", uri="/index", qop="auth", cnonce="1741284305531", response="76c051465a85590a7dd2355cf77588e7"'
    )
  })

  it('should use timestamp cnonce', () => {
    expect(
      createDigest({
        realm: 'digest-h',
        username: 'user',
        password: '123456',
        method: 'GET',
        uri: '/index'
      })
    ).not.toEqual(
      'Digest username="user",realm="digest-h", uri="/index", qop="auth", cnonce="1741284305531", response="76c051465a85590a7dd2355cf77588e7"'
    )
  })
})

describe('createDigest', () => {
  it('should not valid cnone expried', () => {
    expect(
      validDigest({
        method: 'GET',
        digest:
          'Digest username="user",realm="digest-h",uri="/index",qop="auth",cnonce="1741284305531",response="76c051465a85590a7dd2355cf77588e7"',
        password: '123456'
      })
    ).toBe(false)
  })

  it('should not valid with wrong password', () => {
    expect(
      validDigest({
        method: 'GET',
        digest: createDigest({
          realm: 'digest-h',
          username: 'user',
          password: '123456',
          method: 'GET',
          uri: '/index'
        }),
        password: '654321'
      })
    ).toBe(false)
  })

  it('should valid with normal case', () => {
    expect(
      validDigest({
        method: 'GET',
        digest: createDigest({
          realm: 'digest-h',
          username: 'user',
          password: '123456',
          method: 'GET',
          uri: '/index'
        }),
        password: '123456'
      })
    ).toBe(true)
  })

  it('should support lower case method', () => {
    expect(
      validDigest({
        method: 'get',
        digest: createDigest({
          realm: 'digest-h',
          username: 'user',
          password: '123456',
          method: 'GET',
          uri: '/index'
        }),
        password: '123456'
      })
    ).toBe(true)
  })

  it('should support needs', () => {
    expect(
      validDigest(
        {
          method: 'get',
          digest: createDigest({
            realm: 'digest-h',
            username: 'user',
            password: '123456',
            method: 'GET',
            uri: '/index'
          }),
          password: '123456'
        },
        {
          needs: ['username', 'realm', 'uri', 'qop', 'cnonce', 'nonce']
        }
      )
    ).toBe(false)
  })
})
