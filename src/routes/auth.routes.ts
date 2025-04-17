import { Router } from 'express';
import authController from '../controllers/auth.controller';
import { authenticate } from '../middlewares/auth.middleware';
import {
  registerValidation,
  loginValidation,
  resetPasswordRequestValidation,
  resetPasswordValidation,
  verifyEmailValidation,
  refreshTokenValidation,
  updateProfileValidation,
} from '../middlewares/validation.middleware';
import supabaseService from '../services/supabase.service';
import config from '../config';

const router = Router();

// Public routes
router.post('/register', registerValidation, authController.register);
router.post('/login', loginValidation, authController.login);
router.post('/logout', authController.logout);
router.post('/refresh', refreshTokenValidation, authController.refreshToken);
router.post('/reset-password-request', resetPasswordRequestValidation, authController.requestPasswordReset);
router.post('/reset-password', resetPasswordValidation, authController.resetPassword);
router.post('/verify-email', verifyEmailValidation, authController.verifyEmail);
router.post('/resend-verification-email', resetPasswordRequestValidation, authController.resendVerificationEmail);

// OAuth routes
router.get('/oauth/:provider', authController.initiateOAuth);
router.get('/oauth/:provider/callback', authController.handleOAuthCallback);

// Protected routes (require authentication)
router.get('/profile', authenticate, authController.getCurrentUser);
router.put('/profile', authenticate, updateProfileValidation, authController.updateProfile);

// Development-only routes for debugging
if (config.env === 'development') {
  router.get('/debug/database', async (req, res) => {
    const dbInfo = await supabaseService.getDatabaseInfo();
    res.json({
      success: true,
      data: dbInfo
    });
  });
  
  router.get('/debug/config', (req, res) => {
    // Return limited config info for debugging
    res.json({
      success: true,
      data: {
        env: config.env,
        supabaseUrl: config.supabase.url,
        hasSupabaseKey: !!config.supabase.key,
        corsOrigins: config.security.cors.origin,
      }
    });
  });
}

export default router; 