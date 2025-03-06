import { createDigest } from '../src'

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
      'Digest username="user",realm="digest-h",uri="/index",qop="auth",cnonce="1741284305531",response="76c051465a85590a7dd2355cf77588e7"'
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
      'Digest username="user",realm="digest-h",uri="/index",qop="auth",cnonce="1741284305531",response="76c051465a85590a7dd2355cf77588e7"'
    )
  })
})
