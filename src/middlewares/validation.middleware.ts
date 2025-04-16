import { Request, Response, NextFunction } from 'express';
import { body, param, validationResult } from 'express-validator';
import { StatusCodes } from 'http-status-codes';

// Middleware to check validation results
export const validate = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Format errors
    const formattedErrors: Record<string, string[]> = {};
    errors.array().forEach((error) => {
      if (!formattedErrors[error.path]) {
        formattedErrors[error.path] = [];
      }
      formattedErrors[error.path].push(error.msg);
    });

    return res.status(StatusCodes.BAD_REQUEST).json({
      success: false,
      message: 'Validation Error',
      errors: formattedErrors,
    });
  }
  next();
};

// Validation rules for registration
export const registerValidation = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters'),
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters'),
  body('displayName')
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Display name must be between 3 and 30 characters'),
  validate,
];

// Validation rules for login
export const loginValidation = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  validate,
];

// Validation rules for password reset request
export const resetPasswordRequestValidation = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  validate,
];

// Validation rules for password reset
export const resetPasswordValidation = [
  body('token')
    .notEmpty()
    .withMessage('Reset token is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  validate,
];

// Validation rules for email verification
export const verifyEmailValidation = [
  body('token')
    .notEmpty()
    .withMessage('Verification token is required'),
  validate,
];

// Validation rules for token refresh
export const refreshTokenValidation = [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required'),
  validate,
];

// Validation rules for updating user profile
export const updateProfileValidation = [
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters'),
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters'),
  body('displayName')
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Display name must be between 3 and 30 characters'),
  body('bio')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Bio must be less than 500 characters'),
  body('avatarUrl')
    .optional()
    .trim()
    .isURL()
    .withMessage('Avatar URL must be a valid URL'),
  validate,
]; 