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
router.post('/register', registerValidation, authController.register as any);
router.post('/login', loginValidation, authController.login as any);
router.post('/logout', authController.logout as any);
router.post('/refresh', refreshTokenValidation, authController.refreshToken as any);
router.post('/reset-password-request', resetPasswordRequestValidation, authController.requestPasswordReset as any);
router.post('/reset-password', resetPasswordValidation, authController.resetPassword as any);
router.post('/verify-email', verifyEmailValidation, authController.verifyEmail as any);
router.post('/resend-verification-email', resetPasswordRequestValidation, authController.resendVerificationEmail as any);

// OAuth routes
router.get('/oauth/:provider', authController.initiateOAuth as any);
router.get('/oauth/:provider/callback', authController.handleOAuthCallback as any);

// Protected routes (require authentication)
router.get('/profile', authenticate as any, authController.getCurrentUser as any);
router.put('/profile', authenticate as any, updateProfileValidation, authController.updateProfile as any);
router.post('/create-subscription', authenticate as any, authController.createSubscription as any);
router.get('/profile-data/:userId?', authenticate as any, authController.getProfileData as any);

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