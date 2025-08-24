module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src/', '<rootDir>/tests/'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        diagnostics: false
      }
    ]
  },
  moduleNameMapper: {
    '@/(.*)': '<rootDir>/src/$1',
  },
  collectCoverageFrom: [
    'src/**/*.ts', 
    '!src/**/*.d.ts',
    '!src/server.ts',
    '!src/config.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'json-summary'],
  coverageThreshold: {
    global: {
      lines: 0,
      statements: 0,
      branches: 0,
      functions: 0
    }
  },
  passWithNoTests: true,
  verbose: true,
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testEnvironmentOptions: {
    url: 'http://localhost/'
  },
  forceExit: true,
  detectOpenHandles: true,
} 