module.exports = {
  testEnvironment: 'jsdom',
  transform: { '^.+\\.js$': 'babel-jest' },
  testMatch: ['**/static/js/__tests__/**/*.test.js'],
  collectCoverageFrom: ['static/js/**/*.js', '!static/js/service-worker.js'],
  transformIgnorePatterns: ['/node_modules/'],
  setupFiles: ['<rootDir>/static/js/__tests__/setup.js'],
};
