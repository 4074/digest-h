module.exports = {
  verbose: true,
  roots: ['test'],
  transform: {
    '^.+\\.ts$': 'ts-jest'
  },
  testEnvironment: 'node',
  testTimeout: 10000,
  collectCoverage: true,
  coveragePathIgnorePatterns: ['/node_modules/', '/test/']
}