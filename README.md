# SK8 Authentication Microservice

A standalone authentication microservice for a React Native skateboarding app that uses Supabase as the database. This service provides a complete authentication system with JWT token management.

## Features

- **Complete Authentication System**:
  - Email/password registration and login
  - Social authentication (Google, Facebook, Twitter)
  - Password reset functionality
  - Email verification
  - JWT token management
  - Refresh token handling

- **RESTful API Endpoints**:
  - User registration (`/auth/register`)
  - User login (`/auth/login`)
  - Password reset (`/auth/reset-password`)
  - Email verification (`/auth/verify-email`)
  - Token refresh (`/auth/refresh`)
  - User profile management (`/auth/profile`)
  - OAuth callbacks for social providers (`/auth/oauth/provider`)

- **Security Features**:
  - Rate limiting to prevent brute force attacks
  - Input validation and sanitization
  - CORS configuration
  - Proper error handling without leaking sensitive information
  - JWT-based authentication

## Tech Stack

- Node.js with Express
- TypeScript
- Supabase for Authentication and Database
- JWT for token management
- Docker for containerization
- Jest for testing

## Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- Docker and Docker Compose (for containerized setup)
- Supabase account and project

### Environment Variables

Create a `.env` file based on the `.env.example`:

```bash
# Server Configuration
NODE_ENV=development
PORT=3000
API_PREFIX=/api/v1

# JWT Configuration
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRES_IN=1h
JWT_REFRESH_SECRET=your-jwt-refresh-secret-key
JWT_REFRESH_EXPIRES_IN=7d

# Supabase Configuration
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-service-key
SUPABASE_JWT_SECRET=your-supabase-jwt-secret

# Email Configuration
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=your-email@example.com
EMAIL_PASS=your-email-password
EMAIL_FROM=no-reply@sk8app.com

# Social Auth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/api/v1/auth/oauth/google/callback

FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret
FACEBOOK_CALLBACK_URL=http://localhost:3000/api/v1/auth/oauth/facebook/callback

TWITTER_CONSUMER_KEY=your-twitter-consumer-key
TWITTER_CONSUMER_SECRET=your-twitter-consumer-secret
TWITTER_CALLBACK_URL=http://localhost:3000/api/v1/auth/oauth/twitter/callback

# Security
CORS_ORIGIN=http://localhost:3000,https://sk8app.com
RATE_LIMIT_WINDOW_MS=15*60*1000
RATE_LIMIT_MAX=100
```

### Installation

#### Using npm

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run tests
npm test
```

#### Using Docker

```bash
# Start with Docker Compose
docker-compose up

# Stop services
docker-compose down

# If you make changes to the dependencies
docker-compose up --build
```

## API Documentation

### Authentication Endpoints

#### Register a new user

```
POST /api/v1/auth/register
```

Request Body:
```json
{
  "email": "user@example.com",
  "password": "Password123",
  "firstName": "John", // optional
  "lastName": "Doe", // optional
  "displayName": "johndoe" // optional
}
```

Response:
```json
{
  "success": true,
  "message": "User registered successfully. Please check your email to verify your account."
}
```

#### Login a user

```
POST /api/v1/auth/login
```

Request Body:
```json
{
  "email": "user@example.com",
  "password": "Password123"
}
```

Response:
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "user-uuid",
      "email": "user@example.com",
      "emailVerified": true
    },
    "tokens": {
      "accessToken": "jwt-access-token",
      "refreshToken": "jwt-refresh-token"
    }
  }
}
```

#### Logout a user

```
POST /api/v1/auth/logout
```

Request Body:
```json
{
  "refreshToken": "jwt-refresh-token" // optional if stored in cookie
}
```

Response:
```json
{
  "success": true,
  "message": "Logout successful"
}
```

#### Refresh Token

```
POST /api/v1/auth/refresh
```

Request Body:
```json
{
  "refreshToken": "jwt-refresh-token"
}
```

Response:
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "tokens": {
      "accessToken": "new-jwt-access-token",
      "refreshToken": "new-jwt-refresh-token"
    }
  }
}
```

#### Request Password Reset

```
POST /api/v1/auth/reset-password-request
```

Request Body:
```json
{
  "email": "user@example.com"
}
```

Response:
```json
{
  "success": true,
  "message": "Password reset link sent to your email"
}
```

#### Reset Password

```
POST /api/v1/auth/reset-password
```

Request Body:
```json
{
  "token": "reset-password-token",
  "password": "NewPassword123"
}
```

Response:
```json
{
  "success": true,
  "message": "Password has been reset successfully"
}
```

#### Verify Email

```
POST /api/v1/auth/verify-email
```

Request Body:
```json
{
  "token": "email-verification-token"
}
```

Response:
```json
{
  "success": true,
  "message": "Email verified successfully"
}
```

#### Get User Profile (Protected)

```
GET /api/v1/auth/profile
```

Headers:
```
Authorization: Bearer jwt-access-token
```

Response:
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "user-uuid",
      "email": "user@example.com",
      "role": "user",
      "isEmailVerified": true,
      "profile": {
        "firstName": "John",
        "lastName": "Doe",
        "displayName": "johndoe",
        "bio": "Skateboarder and developer",
        "avatarUrl": "https://example.com/avatar.jpg"
      }
    }
  }
}
```

#### Update User Profile (Protected)

```
PUT /api/v1/auth/profile
```

Headers:
```
Authorization: Bearer jwt-access-token
```

Request Body:
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "displayName": "johndoe",
  "bio": "Passionate skateboarder and developer",
  "avatarUrl": "https://example.com/new-avatar.jpg"
}
```

Response:
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "data": {
    "profile": {
      "id": "profile-uuid",
      "userId": "user-uuid",
      "firstName": "John",
      "lastName": "Doe",
      "displayName": "johndoe",
      "bio": "Passionate skateboarder and developer",
      "avatarUrl": "https://example.com/new-avatar.jpg",
      "updatedAt": "2023-07-20T15:30:00Z"
    }
  }
}
```

#### Social Authentication

To initiate social authentication:

```
GET /api/v1/auth/oauth/google
GET /api/v1/auth/oauth/facebook
GET /api/v1/auth/oauth/twitter
```

The user will be redirected to the respective OAuth provider for authentication.

## Integration with React Native Client

To integrate this authentication service with a React Native client:

1. Make requests to the authentication endpoints
2. Store the JWT tokens securely using a library like `@react-native-async-storage/async-storage` or `react-native-keychain`
3. Include the access token in the `Authorization` header for protected requests
4. Implement token refresh logic when access token expires

Example React Native code for login:

```javascript
const login = async (email, password) => {
  try {
    const response = await fetch('https://your-auth-service.com/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });
    
    const data = await response.json();
    
    if (data.success) {
      // Store tokens
      await AsyncStorage.setItem('accessToken', data.data.tokens.accessToken);
      await AsyncStorage.setItem('refreshToken', data.data.tokens.refreshToken);
      
      // Store user info
      await AsyncStorage.setItem('user', JSON.stringify(data.data.user));
      
      return data.data.user;
    } else {
      throw new Error(data.message);
    }
  } catch (error) {
    console.error('Login failed:', error);
    throw error;
  }
};
```

## Supabase Setup

1. Create a new Supabase project
2. Enable the Authentication feature
3. Configure email templates for verification and password reset
4. Set up OAuth providers (Google, Facebook, Twitter)
5. Create a `user_profiles` table with the following schema:

```sql
CREATE TABLE public.user_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL UNIQUE,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    display_name VARCHAR(30),
    bio TEXT,
    avatar_url TEXT,
    preferences JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add Row Level Security policies
ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view their own profile
CREATE POLICY user_profile_select_policy ON public.user_profiles
    FOR SELECT USING (
        auth.uid() = user_id
    );

-- Policy: Users can update their own profile
CREATE POLICY user_profile_update_policy ON public.user_profiles
    FOR UPDATE USING (
        auth.uid() = user_id
    );
```

## Deployment

### Deploy with Docker

1. Build the production Docker image:
   ```bash
   docker build -t sk8-auth-service:production .
   ```

2. Run the container:
   ```bash
   docker run -p 3000:3000 --env-file .env sk8-auth-service:production
   ```

### Deploy to Cloud Providers

#### AWS Elastic Beanstalk

1. Create a new Elastic Beanstalk application
2. Choose Docker as the platform
3. Upload the source code or connect to your repository
4. Configure environment variables in the Elastic Beanstalk console

#### Heroku

1. Create a new Heroku app
2. Add the Docker buildpack
3. Push your code to Heroku:
   ```bash
   heroku container:push web
   heroku container:release web
   ```
4. Configure environment variables in the Heroku dashboard

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License. 