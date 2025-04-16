import { Request } from 'express';

// User interfaces
export interface IUser {
  id: string;
  email: string;
  role: UserRole;
  isEmailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface IUserProfile {
  id: string;
  userId: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  bio?: string;
  avatarUrl?: string;
  preferences?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

// Auth interfaces
export interface IAuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface ILoginCredentials {
  email: string;
  password: string;
}

export interface IRegistrationData {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
}

export interface IPasswordReset {
  token: string;
  password: string;
}

export interface IEmailVerification {
  token: string;
}

export interface ITokenRefresh {
  refreshToken: string;
}

// Request with user
export interface AuthenticatedRequest extends Request {
  user?: IUser;
}

// Enums
export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
}

// OAuth Providers
export type OAuthProvider = 'google' | 'facebook' | 'twitter';

// API Response
export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
  errors?: Record<string, string[]>;
} 