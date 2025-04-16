import { Request, Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { ValidationError } from 'express-validator';

// Custom error class
export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(message: string, statusCode: number, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Not found error handler
export const notFoundHandler = (req: Request, res: Response, next: NextFunction): void => {
  const error = new AppError(`Not Found - ${req.originalUrl}`, StatusCodes.NOT_FOUND);
  next(error);
};

// Global error handler
export const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Default status code and message
  let statusCode = StatusCodes.INTERNAL_SERVER_ERROR;
  let message = 'Something went wrong';
  let errors: Record<string, string[]> | undefined = undefined;
  let isOperational = false;

  // Handle our own AppError
  if (err instanceof AppError) {
    statusCode = err.statusCode;
    message = err.message;
    isOperational = err.isOperational;
  }

  // Handle validation errors (from express-validator)
  if (Array.isArray(err) && err.length > 0 && (err[0] as any).param) {
    statusCode = StatusCodes.BAD_REQUEST;
    message = 'Validation Error';
    errors = {};
    
    (err as unknown as ValidationError[]).forEach((error) => {
      if (!errors![error.param]) {
        errors![error.param] = [];
      }
      errors![error.param].push(error.msg);
    });
  }

  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    statusCode = StatusCodes.UNAUTHORIZED;
    message = 'Invalid token';
  }

  if (err.name === 'TokenExpiredError') {
    statusCode = StatusCodes.UNAUTHORIZED;
    message = 'Token expired';
  }

  // Handle Supabase errors
  if ((err as any).code?.startsWith('P') || (err as any).code === '23505') {
    statusCode = StatusCodes.BAD_REQUEST;
    // For unique constraint violations
    if ((err as any).code === '23505') {
      message = 'Duplicate entry';
    } else {
      message = 'Database error';
    }
  }

  // When in development, log the error
  if (process.env.NODE_ENV === 'development') {
    console.error(err);
  }

  // Don't expose error stack in production
  const responseData: any = {
    success: false,
    message,
    ...(errors && { errors }),
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  };

  // If this is not an operational error in production, give generic message
  if (!isOperational && process.env.NODE_ENV === 'production') {
    responseData.message = 'Something went wrong';
    delete responseData.stack;
  }

  res.status(statusCode).json(responseData);
}; 