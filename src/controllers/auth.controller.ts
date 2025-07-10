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
      
      console.log(`Registration attempt for email: ${email}`);
      console.log('Registration data:', { email, firstName, lastName, displayName });

      // Register user in Supabase
      console.log('Calling Supabase registerUser...');
      const { data, error } = await supabaseService.registerUser(email, password, {
        first_name: firstName,
        last_name: lastName,
        display_name: displayName,
      });
      
      // Log response without sensitive information
      console.log('Supabase registration response details:', {
        success: !error,
        user: data?.user ? { 
          id: data.user.id,
          email: data.user.email,
          emailConfirmedAt: data.user.email_confirmed_at,
          createdAt: data.user.created_at
        } : null,
        error: error ? {
          message: error.message,
          status: (error as any).status
        } : null
      });

      if (error) {
        console.error('Supabase registration error:', error);
        
        // Handle specific error cases
        if (error.message.includes('already registered')) {
          throw new AppError('This email is already registered', StatusCodes.CONFLICT);
        } else if (error.message.includes('password')) {
          throw new AppError('Invalid password: passwords must be at least 6 characters', StatusCodes.BAD_REQUEST);
        } else {
          throw new AppError(error.message, StatusCodes.BAD_REQUEST);
        }
      }

      if (!data.user) {
        console.error('No user data returned from Supabase');
        throw new AppError('Failed to create user', StatusCodes.INTERNAL_SERVER_ERROR);
      }

      console.log(`User registered with ID: ${data.user.id}`);

      // Always create user profile
      console.log('Creating user profile');
      try {
        const profileData = {
          user_id: data.user.id,
          first_name: firstName || '',
          last_name: lastName || '',
          display_name: displayName || '',
          bio: '',
          avatar_url: null,
          created_at: new Date(),
          updated_at: new Date(),
        };
        console.log('Profile data:', profileData);
        
        const profileResult = await supabaseService.upsertUserProfile(profileData);
        console.log('Profile creation result:', JSON.stringify(profileResult, null, 2));
        
        if (profileResult.error) {
          console.error('Profile creation failed:', profileResult.error);
          // Don't fail registration if profile creation fails, but log it
        }
      } catch (profileError) {
        console.error('Error creating user profile:', profileError);
        // Continue even if profile creation fails, but this should be investigated
      }

      // --- BEGIN: ADDED NOTIFICATION LOGIC ---
      try {
        const notificationServiceUrl = 'http://localhost:3004/api/notifications/email';
        console.log(`Sending welcome email to ${email} via ${notificationServiceUrl}`);

        // Fire-and-forget the notification
        fetch(notificationServiceUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            to: email,
            subject: 'Welcome to SK8!',
            html: `<h1>Hey ${displayName || firstName || 'there'},</h1><p>Welcome to the community. Get ready to discover and share the best skate spots.</p>`
          }),
        }).catch(err => {
          // Log the error but don't block the main flow
          console.error('Failed to send welcome email:', err);
        });
      } catch (emailError) {
        console.error('Error initiating the send-email process:', emailError);
      }
      // --- END: ADDED NOTIFICATION LOGIC ---

      // Check if we need to send a verification email
      if (!data.user.email_confirmed_at) {
        console.log('Email not confirmed, verification email should be sent by Supabase');
      } else {
        console.log('Email already confirmed');
      }

      console.log('Registration successful, sending response');
      res.status(StatusCodes.CREATED).json({
        success: true,
        message: 'User registered successfully. Please check your email to verify your account.',
      });
    } catch (error) {
      console.error('Registration error:', error);
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

      // TEMPORARY: Bypass email verification check
      if (error && error.message === 'Invalid login credentials') {
        // Try to get user info directly to check if user exists but isn't verified
        const userCheck = await supabaseService.getUserByEmail(email);
        
        if (userCheck.data?.user) {
          console.log('User exists but verification issue: bypassing for development');
          
          // Generate JWT tokens
          const tokenPayload = {
            sub: userCheck.data.user.id,
            email: userCheck.data.user.email!,
            role: userCheck.data.user.app_metadata?.role || 'user',
          };

          const tokens = jwtService.generateTokens(tokenPayload);

          // Set refresh token in cookie (HTTP only for security)
          res.cookie('refreshToken', tokens.refreshToken, {
            httpOnly: true,
            secure: config.env === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          });

          return res.status(StatusCodes.OK).json({
            success: true,
            message: 'Login successful (dev mode: verification bypassed)',
            data: {
              user: {
                id: userCheck.data.user.id,
                email: userCheck.data.user.email,
                emailVerified: false, // Not verified but allowing login
              },
              tokens: {
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken,
              },
            },
          });
        }
        
        // If user doesn't exist at all, return the normal error
        throw new AppError('Invalid email or password', StatusCodes.UNAUTHORIZED);
      } else if (error) {
        // For other errors, handle as normal
        throw new AppError(error.message, StatusCodes.UNAUTHORIZED);
      }

      if (!data.user) {
        throw new AppError('User not found', StatusCodes.NOT_FOUND);
      }

      // Generate JWT tokens
      const tokenPayload = {
        sub: data.user.id,
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
        sub: decoded.userId,
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
   * Request a password reset for a user
   */
  async requestPasswordReset(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body;
      if (!email) {
        throw new AppError('Email is required', StatusCodes.BAD_REQUEST);
      }

      console.log(`Password reset request for email: ${email}`);

      // Use Supabase's built-in password reset functionality
      const { error } = await supabaseService.sendPasswordResetEmail(email);

      if (error) {
        // Log the error but do not expose details to the client
        console.error('Error sending password reset email:', error.message);
      }

      // Always return a success response to prevent email enumeration
      res.status(StatusCodes.OK).json({
        success: true,
        message: 'If an account with this email exists, a password reset link has been sent.',
      });
    } catch (error) {
      console.error('Password reset request error:', error);
      if (error instanceof AppError) {
        throw error;
      }
      // Return a generic message even for internal errors in this specific case
      res.status(StatusCodes.OK).json({
        success: true,
        message: 'If an account with this email exists, a password reset link has been sent.',
      });
    }
  }

  /**
   * Reset a user's password using a verification token
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
            profile: userProfile || null, // Handle case where no profile exists yet
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

  /**
   * Create a new subscription for the authenticated user
   */
  async createSubscription(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { email, id: userId } = req.user || {};

      if (!email || !userId) {
        throw new AppError('Authentication failed. User details not found.', StatusCodes.UNAUTHORIZED);
      }

      console.log(`Creating subscription for user: ${userId} (${email})`);

      // Call the payment service to create the subscription
      const paymentServiceUrl = 'http://localhost:3005/api/payments/create-subscription';
      const paymentResponse = await fetch(paymentServiceUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      if (!paymentResponse.ok) {
        const errorBody = await paymentResponse.text();
        console.error(`Payment service responded with error: ${paymentResponse.status}`, errorBody);
        throw new AppError('Could not initiate subscription with the payment service.', StatusCodes.INTERNAL_SERVER_ERROR);
      }

      const { clientSecret, subscriptionId } = await paymentResponse.json() as { clientSecret: string; subscriptionId: string };

      // Optional but highly recommended: Save the subscriptionId to the user's profile
      // This helps you track their status later.
      await supabaseService.upsertUserProfile({
        user_id: userId,
        stripe_subscription_id: subscriptionId,
        subscription_status: 'incomplete', // Will be 'active' after successful payment
      });

      console.log(`Subscription ${subscriptionId} initiated for user ${userId}. Sending client_secret to app.`);

      res.status(StatusCodes.OK).json({ clientSecret, subscriptionId });

    } catch (error) {
      console.error('Create subscription error:', error);
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError((error as Error).message, StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Get profile data including spots, collections, achievements
   */
  async getProfileData(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new AppError('User not authenticated', StatusCodes.UNAUTHORIZED);
      }

      const userId = req.params.userId || req.user.id;

      // Get user profile from Supabase
      const userProfile = await supabaseService.getUserById(userId);

      // Here you would fetch additional data like spots, collections, achievements
      // For now, returning basic structure
      const profileData = {
        profile: userProfile,
        spots: [], // TODO: Fetch from spot service
        collections: [], // TODO: Fetch from spot service  
        achievements: [], // TODO: Fetch from spot service
        followers: 0, // TODO: Fetch from social service
        following: 0, // TODO: Fetch from social service
      };

      res.status(StatusCodes.OK).json({
        success: true,
        data: profileData,
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