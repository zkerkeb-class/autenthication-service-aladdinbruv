import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import { Express } from 'express';
import config from '../config';

/**
 * Configure security middleware for the Express app
 */
export const configureSecurityMiddleware = (app: Express): void => {
  // Set security HTTP headers with Helmet
  app.use(helmet());

  // Configure CORS
  app.use(
    cors({
      origin: config.security.cors.origin,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    })
  );

  // Global rate limiter
  app.use(
    rateLimit({
      windowMs: config.security.rateLimit.windowMs,
      max: config.security.rateLimit.max,
      standardHeaders: true,
      legacyHeaders: false,
      message: {
        success: false,
        message: 'Too many requests, please try again later.',
      },
    })
  );

  // Strict rate limiter for auth endpoints
  const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      success: false,
      message: 'Too many authentication attempts, please try again later.',
    },
  });

  // Apply the auth rate limiter to specific routes
  app.use(['/api/v1/auth/login', '/api/v1/auth/register', '/api/v1/auth/reset-password'], authRateLimiter);
};

/**
 * Create a custom rate limiter for specific routes
 */
export const createRateLimiter = (windowMs: number, max: number, message: string) => {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      success: false,
      message,
    },
  });
}; 