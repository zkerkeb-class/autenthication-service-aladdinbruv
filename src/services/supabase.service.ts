import { createClient, SupabaseClient } from '@supabase/supabase-js';
import config from '../config';

class SupabaseService {
  private client: SupabaseClient;

  constructor() {
    this.client = createClient(config.supabase.url, config.supabase.key);
  }

  /**
   * Get the Supabase client instance
   */
  getClient(): SupabaseClient {
    return this.client;
  }

  /**
   * Register a new user with email and password
   */
  async registerUser(email: string, password: string) {
    return this.client.auth.signUp({
      email,
      password,
    });
  }

  /**
   * Login a user with email and password
   */
  async loginUser(email: string, password: string) {
    return this.client.auth.signInWithPassword({
      email,
      password,
    });
  }

  /**
   * Log out a user
   */
  async logoutUser(refreshToken: string) {
    return this.client.auth.signOut();
  }

  /**
   * Send password reset email
   */
  async resetPassword(email: string) {
    return this.client.auth.resetPasswordForEmail(email, {
      redirectTo: `${config.apiPrefix}/auth/reset-password-callback`,
    });
  }

  /**
   * Update user's password
   */
  async updatePassword(accessToken: string, password: string) {
    this.client.auth.setSession({ access_token: accessToken, refresh_token: '' });
    return this.client.auth.updateUser({ password });
  }

  /**
   * Send verification email
   */
  async sendVerificationEmail(email: string) {
    return this.client.auth.resend({
      type: 'signup',
      email,
      options: {
        redirectTo: `${config.apiPrefix}/auth/verify-email-callback`,
      },
    });
  }

  /**
   * Verify email with token
   */
  async verifyEmail(token: string) {
    return this.client.auth.verifyOtp({
      token_hash: token,
      type: 'email',
    });
  }

  /**
   * Get user by ID
   */
  async getUserById(userId: string) {
    const { data, error } = await this.client
      .from('user_profiles')
      .select('*')
      .eq('user_id', userId)
      .single();
    
    if (error) throw error;
    return data;
  }

  /**
   * Create or update user profile
   */
  async upsertUserProfile(profile: any) {
    return this.client
      .from('user_profiles')
      .upsert(profile, { onConflict: 'user_id' })
      .select();
  }

  /**
   * Refresh token
   */
  async refreshToken(refreshToken: string) {
    return this.client.auth.refreshSession({ refresh_token: refreshToken });
  }

  /**
   * Sign in with OAuth provider
   */
  getOAuthSignInUrl(provider: 'google' | 'facebook' | 'twitter') {
    return this.client.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: config.oauth[provider].callbackUrl,
      },
    });
  }

  /**
   * Get user by refresh token
   */
  async getUserByToken(token: string) {
    return this.client.auth.getUser(token);
  }
}

export default new SupabaseService(); 