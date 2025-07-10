import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import jwtService from '../services/jwt.service';
import supabaseService from '../services/supabase.service';
import { AuthenticatedRequest, UserRole } from '../types';

/**
 * Authentication middleware to verify JWT token
 */
export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    // Extract token
    const token = authHeader.split(' ')[1];
    if (!token) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: 'Authentication token is required',
      });
      return;
    }

    // DEVELOPMENT ONLY: Allow mock token for testing
    if (token === 'mock-development-token' && process.env.NODE_ENV === 'development') {
      req.user = {
        id: 'test-user-123',
        email: 'test@example.com',
        role: UserRole.USER,
        isEmailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      return next();
    }

    try {
      // Verify token
      const decoded = jwtService.verifyAccessToken(token);
      
      // Get user from Supabase
      const { data, error } = await supabaseService.getClient().auth.getUser(token);
      
      if (error || !data.user) {
        res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: 'Invalid or expired token',
        });
        return;
      }

      // Attach user to request
      req.user = {
        id: data.user.id,
        email: data.user.email || '',
        role: (data.user.app_metadata?.role as UserRole) || UserRole.USER,
        isEmailVerified: data.user.email_confirmed_at !== null,
        createdAt: new Date(data.user.created_at),
        updatedAt: new Date(data.user.updated_at || data.user.created_at),
      };

      next();
    } catch (error) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: 'Invalid or expired token',
      });
    }
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: 'Authentication error',
    });
  }
};

/**
 * Role-based authorization middleware
 */
export const authorize = (roles: UserRole[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        message: 'You do not have permission to access this resource',
      });
      return;
    }

    next();
  };
};

/**
 * Middleware to verify email
 */
export const verifyEmail = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(StatusCodes.UNAUTHORIZED).json({
      success: false,
      message: 'Authentication required',
    });
    return;
  }

  if (!req.user.isEmailVerified) {
    res.status(StatusCodes.FORBIDDEN).json({
      success: false,
      message: 'Email verification required',
    });
    return;
  }

  next();
}; 