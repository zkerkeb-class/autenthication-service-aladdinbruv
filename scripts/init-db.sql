-- This is a simplified version of Supabase's auth schema for local development
-- In production, you would use the Supabase-hosted service

-- Create auth schema
CREATE SCHEMA IF NOT EXISTS auth;

-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create user_profiles table
CREATE TABLE IF NOT EXISTS public.user_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL UNIQUE,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    display_name VARCHAR(30),
    bio TEXT,
    avatar_url TEXT,
    preferences JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create auth.users table (simplified version)
CREATE TABLE IF NOT EXISTS auth.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    encrypted_password VARCHAR(255) NOT NULL,
    email_confirmed_at TIMESTAMP WITH TIME ZONE,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create trigger to automatically create user profile when user is created
CREATE OR REPLACE FUNCTION public.create_user_profile()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.user_profiles(user_id, created_at, updated_at)
    VALUES(NEW.id, NOW(), NOW());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.create_user_profile();

-- Create Row Level Security (RLS) policies
ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only view and edit their own profile
CREATE POLICY user_profile_select_policy ON public.user_profiles
    FOR SELECT USING (
        auth.uid() = user_id
    );

CREATE POLICY user_profile_update_policy ON public.user_profiles
    FOR UPDATE USING (
        auth.uid() = user_id
    );

-- Function to simulate Supabase's auth.uid() for local development
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID AS $$
BEGIN
    -- In a real Supabase setup, this would return the ID of the currently authenticated user
    -- For local development, return NULL or a specific UUID for testing
    RETURN NULL;
END;
$$ LANGUAGE plpgsql; 