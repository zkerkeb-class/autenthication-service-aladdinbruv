import request from 'supertest';
import app from '../src/server';
import supabaseService from '../src/services/supabase.service';

// Mock Supabase service
jest.mock('../src/services/supabase.service');

describe('Auth Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /api/v1/auth/register', () => {
    it('should register a new user successfully', async () => {
      // Mock Supabase register user response
      (supabaseService.registerUser as jest.Mock).mockResolvedValue({
        data: {
          user: {
            id: '12345',
            email: 'test@example.com',
            email_confirmed_at: null,
          },
        },
        error: null,
      });

      // Mock Supabase upsert user profile response
      (supabaseService.upsertUserProfile as jest.Mock).mockResolvedValue({
        data: {
          user_id: '12345',
          first_name: 'John',
          last_name: 'Doe',
        },
        error: null,
      });

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'test@example.com',
          password: 'Password123',
          firstName: 'John',
          lastName: 'Doe',
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('User registered successfully');
    });

    it('should return validation error for invalid email', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'invalid-email',
          password: 'Password123',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Validation Error');
      expect(response.body.errors).toBeDefined();
      expect(response.body.errors.email).toBeDefined();
    });

    it('should return validation error for weak password', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'test@example.com',
          password: 'weak',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Validation Error');
      expect(response.body.errors).toBeDefined();
      expect(response.body.errors.password).toBeDefined();
    });
  });

  describe('POST /api/v1/auth/login', () => {
    it('should login a user successfully', async () => {
      // Mock Supabase login user response
      (supabaseService.loginUser as jest.Mock).mockResolvedValue({
        data: {
          user: {
            id: '12345',
            email: 'test@example.com',
            email_confirmed_at: new Date().toISOString(),
          },
          session: {
            access_token: 'fake-access-token',
            refresh_token: 'fake-refresh-token',
          },
        },
        error: null,
      });

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com',
          password: 'Password123',
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Login successful');
      expect(response.body.data).toBeDefined();
      expect(response.body.data.user).toBeDefined();
      expect(response.body.data.tokens).toBeDefined();
      expect(response.body.data.tokens.accessToken).toBeDefined();
      expect(response.body.data.tokens.refreshToken).toBeDefined();
    });

    it('should return error for invalid credentials', async () => {
      // Mock Supabase login user response for invalid credentials
      (supabaseService.loginUser as jest.Mock).mockResolvedValue({
        data: { user: null, session: null },
        error: { message: 'Invalid credentials' },
      });

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com',
          password: 'WrongPassword',
        });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid email or password');
    });
  });

  // Add more tests for other endpoints as needed
});

// Mock implementation for getCurrentUser to test protected routes
describe('Protected Routes', () => {
  it('should return 401 for unauthenticated requests', async () => {
    const response = await request(app).get('/api/v1/auth/profile');

    expect(response.status).toBe(401);
    expect(response.body.success).toBe(false);
  });
}); 