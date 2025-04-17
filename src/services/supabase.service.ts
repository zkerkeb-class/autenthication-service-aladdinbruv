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
    console.log(`Attempting to register user with email: ${email} using Supabase`);
    console.log(`Supabase URL: ${config.supabase.url}`);
    
    try {
      // Define the redirect URL for email confirmation
      const redirectUrl = process.env.NODE_ENV === 'production'
        ? `${config.frontendUrl}/auth/verify-email`
        : 'http://localhost:3000/auth/verify-email';
      
      console.log(`Email confirmation redirect URL: ${redirectUrl}`);
      
      const { data, error } = await this.client.auth.signUp({
        email,
        password,
        options: {
          emailRedirectTo: redirectUrl
        }
      });
      
      console.log('Supabase registration result:', {
        user: data?.user ? { id: data.user.id, email: data.user.email } : null,
        error: error ? { message: error.message } : null,
        session: data?.session ? 'Session created' : 'No session'
      });
      
      return { data, error };
    } catch (error) {
      console.error('Unexpected error during Supabase registration:', error);
      throw error;
    }
  }

  /**
   * Login a user with email and password
   */
  async loginUser(email: string, password: string) {
    console.log(`Attempting to log in user with email: ${email}`);
    
    try {
      const { data, error } = await this.client.auth.signInWithPassword({
        email,
        password,
      });
      
      console.log('Supabase login result:', {
        user: data?.user ? { id: data.user.id, email: data.user.email } : null,
        error: error ? { message: error.message } : null
      });
      
      return { data, error };
    } catch (error) {
      console.error('Unexpected error during Supabase login:', error);
      throw error;
    }
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

  /**
   * Get user by email (for development/testing purposes)
   */
  async getUserByEmail(email: string) {
    try {
      // This uses the admin API to check if a user exists 
      // Note: This requires Supabase service role key to work
      console.log(`Looking up user by email: ${email}`);
      
      const { data: users, error } = await this.client.auth.admin.listUsers({
        page: 1,
        perPage: 10,
      });
      
      if (error) {
        console.error('Error looking up user by email:', error);
        return { data: null, error };
      }
      
      // Find the user by email in the returned list
      const user = users.users.find(u => u.email === email);
      
      if (user) {
        console.log(`Found user with email ${email}: ${user.id}`);
        return { data: { user }, error: null };
      } else {
        console.log(`No user found with email ${email}`);
        return { data: null, error: { message: 'User not found' } };
      }
    } catch (error) {
      console.error('Error in getUserByEmail:', error);
      return { data: null, error: error as any };
    }
  }

  /**
   * Get database structure information for debugging
   */
  async getDatabaseInfo() {
    console.log('Fetching database info for debugging');
    const results = {
      connectionStatus: 'unknown',
      serviceVersion: undefined,
      schemaInfo: {
        userProfilesTable: {
          exists: false,
          count: 0,
          fields: []
        },
        authUsers: {
          count: 0,
          sample: []
        }
      },
      errors: []
    };
    
    try {
      // Test connection with a simple health check
      const { data: healthData, error: healthError } = await this.client.rpc('get_service_version');
      
      if (healthError) {
        console.error('Connection test failed:', healthError);
        results.connectionStatus = 'failed';
        results.errors.push({
          context: 'connection_test',
          message: healthError.message
        });
      } else {
        results.connectionStatus = 'connected';
        results.serviceVersion = healthData;
        console.log(`Connected to Supabase, service version: ${healthData}`);
      }
      
      // Get schema information for user_profiles table
      const { data: schemaData, error: schemaError } = await this.client.rpc('get_schema_info', {
        table_name: 'user_profiles'
      });
      
      if (schemaError) {
        console.error('Error getting schema info:', schemaError);
        results.errors.push({
          context: 'schema_info',
          message: schemaError.message
        });
      } else {
        results.schemaInfo.userProfilesTable.exists = true;
        results.schemaInfo.userProfilesTable.fields = schemaData || [];
        console.log('user_profiles schema:', schemaData);
      }
      
      // Check if user_profiles table exists and get count
      const { count: profileCount, error: profileError } = await this.client
        .from('user_profiles')
        .select('*', { count: 'exact', head: true });
      
      if (profileError) {
        console.error('Error checking user_profiles table:', profileError);
        results.errors.push({
          context: 'user_profiles_count',
          message: profileError.message
        });
      } else {
        results.schemaInfo.userProfilesTable.exists = true;
        results.schemaInfo.userProfilesTable.count = profileCount || 0;
        console.log(`user_profiles table exists, count: ${profileCount}`);
      }
      
      // Get info about auth.users
      try {
        const { data: authUsers, error: authUsersError } = await this.client.auth.admin.listUsers({
          page: 1,
          perPage: 5,
        });
        
        if (authUsersError) {
          console.error('Error listing auth users:', authUsersError);
          results.errors.push({
            context: 'auth_users_list',
            message: authUsersError.message
          });
        } else {
          results.schemaInfo.authUsers.count = authUsers?.users?.length || 0;
          
          if (authUsers?.users?.length) {
            authUsers.users.forEach((user, i) => {
              console.log(`User ${i + 1}: ID=${user.id}, Email=${user.email}`);
              results.schemaInfo.authUsers.sample.push({
                id: user.id,
                email: user.email,
                confirmed: !!user.email_confirmed_at
              });
            });
          }
        }
      } catch (authError) {
        console.error('Error checking auth users:', authError);
        results.errors.push({
          context: 'auth_users_check',
          message: (authError as Error).message
        });
      }
      
      return results;
    } catch (error) {
      console.error('Error fetching database info:', error);
      results.connectionStatus = 'error';
      results.errors.push({
        context: 'general',
        message: (error as Error).message
      });
      return results;
    }
  }
}

export default new SupabaseService(); 