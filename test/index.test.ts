import geeting from '../src'

describe('geeting', () => {
  it('should say hello', () => {
    expect(geeting('world')).toEqual('Hello, world!')
  })
})
