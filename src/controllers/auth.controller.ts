import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { AuthenticatedRequest, ILoginCredentials, IRegistrationData, IPasswordReset, IEmailVerification, ITokenRefresh } from '../types';
import supabaseService from '../services/supabase.service';
import jwtService from '../services/jwt.service';
import emailService from '../services/email.service';
import { AppError } from '../middlewares/error.middleware';
import config from '../config';

class AuthController {
  /**
   * Register a new user
   */
  async register(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, firstName, lastName, displayName }: IRegistrationData = req.body;

      // Register user in Supabase
      const { data, error } = await supabaseService.registerUser(email, password);

      if (error) {
        throw new AppError(error.message, StatusCodes.BAD_REQUEST);
      }

      if (!data.user) {
        throw new AppError('Failed to create user', StatusCodes.INTERNAL_SERVER_ERROR);
      }

      // Create user profile if additional info provided
      if (firstName || lastName || displayName) {
        await supabaseService.upsertUserProfile({
          user_id: data.user.id,
          first_name: firstName,
          last_name: lastName,
          display_name: displayName,
          created_at: new Date(),
          updated_at: new Date(),
        });
      }

      // Check if we need to send a verification email
      if (!data.user.email_confirmed_at) {
        // The verification email is handled by Supabase automatically
        // But we could send our own custom email if needed
      }

      res.status(StatusCodes.CREATED).json({
        success: true,
        message: 'User registered successfully. Please check your email to verify your account.',
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Login a user
   */
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password }: ILoginCredentials = req.body;

      // Authenticate user with Supabase
      const { data, error } = await supabaseService.loginUser(email, password);

      if (error) {
        throw new AppError('Invalid email or password', StatusCodes.UNAUTHORIZED);
      }

      if (!data.user) {
        throw new AppError('User not found', StatusCodes.NOT_FOUND);
      }

      // Generate JWT tokens
      const tokenPayload = {
        userId: data.user.id,
        email: data.user.email!,
        role: data.user.app_metadata?.role || 'user',
      };

      const tokens = jwtService.generateTokens(tokenPayload);

      // Set refresh token in cookie (HTTP only for security)
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: config.env === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      res.status(StatusCodes.OK).json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: data.user.id,
            email: data.user.email,
            emailVerified: data.user.email_confirmed_at !== null,
          },
          tokens: {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
          },
        },
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Logout a user
   */
  async logout(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

      if (refreshToken) {
        await supabaseService.logoutUser(refreshToken);
      }

      // Clear the refresh token cookie
      res.clearCookie('refreshToken');

      res.status(StatusCodes.OK).json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken }: ITokenRefresh = req.body;

      // Verify refresh token
      const decoded = jwtService.verifyRefreshToken(refreshToken);

      // Check if user exists and refresh token is valid
      const { data, error } = await supabaseService.refreshToken(refreshToken);

      if (error || !data.session) {
        throw new AppError('Invalid or expired refresh token', StatusCodes.UNAUTHORIZED);
      }

      // Generate new tokens
      const tokenPayload = {
        userId: decoded.userId,
        email: decoded.email,
        role: decoded.role || 'user',
      };

      const newTokens = jwtService.generateTokens(tokenPayload);

      // Set refresh token in cookie (HTTP only for security)
      res.cookie('refreshToken', newTokens.refreshToken, {
        httpOnly: true,
        secure: config.env === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      res.status(StatusCodes.OK).json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          tokens: {
            accessToken: newTokens.accessToken,
            refreshToken: newTokens.refreshToken,
          },
        },
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Invalid refresh token', StatusCodes.UNAUTHORIZED);
    }
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body;

      // Send password reset email via Supabase
      const { error } = await supabaseService.resetPassword(email);

      if (error) {
        throw new AppError(error.message, StatusCodes.BAD_REQUEST);
      }

      res.status(StatusCodes.OK).json({
        success: true,
        message: 'Password reset link sent to your email',
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Reset password with token
   */
  async resetPassword(req: Request, res: Response): Promise<void> {
    try {
      const { token, password }: IPasswordReset = req.body;

      // Update password via Supabase
      const { error } = await supabaseService.updatePassword(token, password);

      if (error) {
        throw new AppError(error.message, StatusCodes.BAD_REQUEST);
      }

      res.status(StatusCodes.OK).json({
        success: true,
        message: 'Password has been reset successfully',
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Verify email with token
   */
  async verifyEmail(req: Request, res: Response): Promise<void> {
    try {
      const { token }: IEmailVerification = req.body;

      // Verify email via Supabase
      const { error } = await supabaseService.verifyEmail(token);

      if (error) {
        throw new AppError(error.message, StatusCodes.BAD_REQUEST);
      }

      res.status(StatusCodes.OK).json({
        success: true,
        message: 'Email verified successfully',
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Get current user
   */
  async getCurrentUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new AppError('User not authenticated', StatusCodes.UNAUTHORIZED);
      }

      // Get user profile from Supabase
      const userProfile = await supabaseService.getUserById(req.user.id);

      res.status(StatusCodes.OK).json({
        success: true,
        data: {
          user: {
            id: req.user.id,
            email: req.user.email,
            role: req.user.role,
            isEmailVerified: req.user.isEmailVerified,
            profile: userProfile,
          },
        },
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Update user profile
   */
  async updateProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new AppError('User not authenticated', StatusCodes.UNAUTHORIZED);
      }

      const { firstName, lastName, displayName, bio, avatarUrl } = req.body;

      // Create the profile object
      const profileData = {
        user_id: req.user.id,
        first_name: firstName,
        last_name: lastName,
        display_name: displayName,
        bio,
        avatar_url: avatarUrl,
        updated_at: new Date(),
      };

      // Update profile in Supabase
      const { data, error } = await supabaseService.upsertUserProfile(profileData);

      if (error) {
        throw new AppError(error.message, StatusCodes.BAD_REQUEST);
      }

      res.status(StatusCodes.OK).json({
        success: true,
        message: 'Profile updated successfully',
        data: {
          profile: data,
        },
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Initiate OAuth login
   */
  async initiateOAuth(req: Request, res: Response): Promise<void> {
    try {
      const { provider } = req.params as { provider: 'google' | 'facebook' | 'twitter' };

      // Validate provider
      if (!['google', 'facebook', 'twitter'].includes(provider)) {
        throw new AppError('Invalid OAuth provider', StatusCodes.BAD_REQUEST);
      }

      // Get OAuth URL from Supabase
      const { data, error } = await supabaseService.getOAuthSignInUrl(provider);

      if (error || !data?.url) {
        throw new AppError('Failed to generate OAuth URL', StatusCodes.INTERNAL_SERVER_ERROR);
      }

      // Redirect to OAuth provider
      res.redirect(data.url);
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Handle OAuth callback
   */
  async handleOAuthCallback(req: Request, res: Response): Promise<void> {
    try {
      const { provider } = req.params;
      const { code } = req.query;

      if (!code) {
        throw new AppError('Authorization code is missing', StatusCodes.BAD_REQUEST);
      }

      // The token exchange is already handled by Supabase
      // Here we would handle any post-authentication logic

      // Redirect to the frontend with success message
      res.redirect(`${config.env === 'production' ? 'https://sk8app.com' : 'http://localhost:3000'}/auth/callback?success=true`);
    } catch (error) {
      // Redirect to the frontend with error message
      res.redirect(`${config.env === 'production' ? 'https://sk8app.com' : 'http://localhost:3000'}/auth/callback?success=false&error=${encodeURIComponent((error as Error).message)}`);
    }
  }

  /**
   * Resend email verification
   */
  async resendVerificationEmail(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body;

      // Resend verification email via Supabase
      const { error } = await supabaseService.sendVerificationEmail(email);

      if (error) {
        throw new AppError(error.message, StatusCodes.BAD_REQUEST);
      }

      res.status(StatusCodes.OK).json({
        success: true,
        message: 'Verification email resent successfully',
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }
}

export default new AuthController(); 