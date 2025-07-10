import jwt from 'jsonwebtoken';
import config from '../config';

interface TokenPayload {
  userId: string;
  email: string;
  [key: string]: any;
}

class JwtService {
  /**
   * Generate an access token
   */
  generateAccessToken(payload: TokenPayload): string {
    const enrichedPayload = {
      ...payload,
      aud: 'authenticated',
      iss: 'https://ajebhzphrstcoyknfqik.supabase.co/auth/v1',
      exp: Math.floor(Date.now() / 1000) + (60 * 60),
    };
    return jwt.sign(enrichedPayload, config.jwt.secret);
  }

  /**
   * Generate a refresh token
   */
  generateRefreshToken(payload: TokenPayload): string {
    return jwt.sign(payload, config.jwt.refreshSecret, {
      expiresIn: config.jwt.refreshExpiresIn,
    });
  }

  /**
   * Verify an access token
   */
  verifyAccessToken(token: string): TokenPayload {
    try {
      return jwt.verify(token, config.jwt.secret) as TokenPayload;
    } catch (error) {
      throw new Error('Invalid access token');
    }
  }

  /**
   * Verify a refresh token
   */
  verifyRefreshToken(token: string): TokenPayload {
    try {
      return jwt.verify(token, config.jwt.refreshSecret) as TokenPayload;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  /**
   * Generate token pair (access and refresh)
   */
  generateTokens(payload: TokenPayload): { accessToken: string; refreshToken: string } {
    const accessToken = this.generateAccessToken(payload);
    const refreshToken = this.generateRefreshToken(payload);
    
    return {
      accessToken,
      refreshToken,
    };
  }

  /**
   * Decode a token without verification
   */
  decodeToken(token: string): TokenPayload | null {
    try {
      return jwt.decode(token) as TokenPayload;
    } catch (error) {
      return null;
    }
  }
}

export default new JwtService(); 