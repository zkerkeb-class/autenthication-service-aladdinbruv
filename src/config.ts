import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from .env file
dotenv.config({ path: path.join(__dirname, '../.env') });

interface Config {
  env: string;
  port: number;
  apiPrefix: string;
  jwt: {
    secret: string;
    expiresIn: string;
    refreshSecret: string;
    refreshExpiresIn: string;
  };
  supabase: {
    url: string;
    key: string;
    jwtSecret: string;
  };
  email: {
    host: string;
    port: number;
    secure: boolean;
    auth: {
      user: string;
      pass: string;
    };
    from: string;
  };
  oauth: {
    google: {
      clientId: string;
      clientSecret: string;
      callbackUrl: string;
    };
    facebook: {
      appId: string;
      appSecret: string;
      callbackUrl: string;
    };
    twitter: {
      consumerKey: string;
      consumerSecret: string;
      callbackUrl: string;
    };
  };
  security: {
    cors: {
      origin: string[];
    };
    rateLimit: {
      windowMs: number;
      max: number;
    };
  };
}

// Validate required environment variables
const requiredEnvVars = [
  'NODE_ENV',
  'PORT',
  'JWT_SECRET',
  'JWT_REFRESH_SECRET',
  'SUPABASE_URL',
  'SUPABASE_KEY',
];

const missingEnvVars = requiredEnvVars.filter((envVar) => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
}

// Parse rate limit window from string expression to number
const parseRateLimitWindow = (): number => {
  const windowMs = process.env.RATE_LIMIT_WINDOW_MS || '15*60*1000';
  try {
    // Using Function constructor to safely evaluate the expression
    return Function(`'use strict'; return (${windowMs})`)();
  } catch (error) {
    return 15 * 60 * 1000; // Default: 15 minutes in milliseconds
  }
};

// Configuration object
const config: Config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  apiPrefix: process.env.API_PREFIX || '/api/v1',
  jwt: {
    secret: process.env.JWT_SECRET!,
    expiresIn: process.env.JWT_EXPIRES_IN || '1h',
    refreshSecret: process.env.JWT_REFRESH_SECRET!,
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },
  supabase: {
    url: process.env.SUPABASE_URL!,
    key: process.env.SUPABASE_KEY!,
    jwtSecret: process.env.SUPABASE_JWT_SECRET || process.env.JWT_SECRET!,
  },
  email: {
    host: process.env.EMAIL_HOST || 'smtp.example.com',
    port: parseInt(process.env.EMAIL_PORT || '587', 10),
    secure: process.env.EMAIL_PORT === '465', // true for port 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER || '',
      pass: process.env.EMAIL_PASS || '',
    },
    from: process.env.EMAIL_FROM || 'no-reply@sk8app.com',
  },
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackUrl: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/api/v1/auth/oauth/google/callback',
    },
    facebook: {
      appId: process.env.FACEBOOK_APP_ID || '',
      appSecret: process.env.FACEBOOK_APP_SECRET || '',
      callbackUrl: process.env.FACEBOOK_CALLBACK_URL || 'http://localhost:3000/api/v1/auth/oauth/facebook/callback',
    },
    twitter: {
      consumerKey: process.env.TWITTER_CONSUMER_KEY || '',
      consumerSecret: process.env.TWITTER_CONSUMER_SECRET || '',
      callbackUrl: process.env.TWITTER_CALLBACK_URL || 'http://localhost:3000/api/v1/auth/oauth/twitter/callback',
    },
  },
  security: {
    cors: {
      origin: (process.env.CORS_ORIGIN || 'http://localhost:3000').split(','),
    },
    rateLimit: {
      windowMs: parseRateLimitWindow(),
      max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
    },
  },
};

export default config; 