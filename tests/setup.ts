// Setup file for Jest tests

// Set a default timeout for tests
jest.setTimeout(30000);

// Mock environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret';
process.env.SUPABASE_URL = 'https://test-supabase-url.com';
process.env.SUPABASE_KEY = 'test-supabase-key'; 