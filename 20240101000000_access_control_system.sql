-- ==============================================================================
-- SUPABASE ACCESS CONTROL (RBAC) & USER CREATION FLAGS SCHEMA (LOVABLE READY)
-- ==============================================================================

-- 1. Enable Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Create Types
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('superadmin', 'admin', 'manager', 'supervisor', 'operator', 'viewer');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE user_status AS ENUM ('active', 'inactive', 'pending', 'suspended');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- 3. Departments Table
CREATE TABLE IF NOT EXISTS public.departments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    code VARCHAR(20) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO public.departments (name, code, description) VALUES
('Administração', 'ADM', 'Gestão administrativa e operacional'),
('Tecnologia da Informação', 'TI', 'Gestão de infraestrutura e sistemas'),
('Recursos Humanos', 'RH', 'Gestão de pessoas e departamento pessoal'),
('Operações', 'OPS', 'Equipe de campo e operacionais'),
('Financeiro', 'FIN', 'Controladoria e finanças')
ON CONFLICT (code) DO NOTHING;

-- 4. Profiles Table (Integrated with auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'viewer',
    status user_status NOT NULL DEFAULT 'active',
    department_id UUID REFERENCES public.departments(id) ON DELETE SET NULL,
    avatar_url TEXT,
    phone VARCHAR(30),
    
    -- Granular User Creation & Access Flags
    can_create_users BOOLEAN NOT NULL DEFAULT FALSE,
    can_edit_users BOOLEAN NOT NULL DEFAULT FALSE,
    can_delete_users BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_roles BOOLEAN NOT NULL DEFAULT FALSE,
    can_view_audit_logs BOOLEAN NOT NULL DEFAULT FALSE,
    can_export_reports BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_system_settings BOOLEAN NOT NULL DEFAULT FALSE,
    require_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    
    custom_flags JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    last_sign_in_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Audit Logs Table
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    actor_email VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. Helper Security Functions (SECURITY DEFINER to prevent RLS recursion)
CREATE OR REPLACE FUNCTION public.is_admin_or_superadmin()
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, auth
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.profiles 
        WHERE id = auth.uid() 
          AND role IN ('superadmin', 'admin') 
          AND status = 'active'
    );
$$;

CREATE OR REPLACE FUNCTION public.has_user_flag(flag_name TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
STABLE
AS $$
DECLARE
    user_prof public.profiles%ROWTYPE;
BEGIN
    SELECT * INTO user_prof FROM public.profiles WHERE id = auth.uid() AND status = 'active';
    IF NOT FOUND THEN RETURN FALSE; END IF;
    IF user_prof.role = 'superadmin' THEN RETURN TRUE; END IF;

    CASE flag_name
        WHEN 'can_create_users' THEN RETURN user_prof.can_create_users;
        WHEN 'can_edit_users' THEN RETURN user_prof.can_edit_users;
        WHEN 'can_delete_users' THEN RETURN user_prof.can_delete_users;
        WHEN 'can_manage_roles' THEN RETURN user_prof.can_manage_roles;
        WHEN 'can_view_audit_logs' THEN RETURN user_prof.can_view_audit_logs;
        WHEN 'can_export_reports' THEN RETURN user_prof.can_export_reports;
        WHEN 'can_manage_system_settings' THEN RETURN user_prof.can_manage_system_settings;
        ELSE RETURN COALESCE((user_prof.custom_flags->>flag_name)::boolean, FALSE);
    END CASE;
END;
$$;

-- 7. Trigger on auth.users Signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    default_role user_role := 'viewer';
    is_first_user BOOLEAN := FALSE;
    meta_name TEXT;
    can_create BOOLEAN := FALSE;
    can_edit BOOLEAN := FALSE;
    can_delete BOOLEAN := FALSE;
    can_roles BOOLEAN := FALSE;
    can_audit BOOLEAN := FALSE;
    can_export BOOLEAN := FALSE;
    can_settings BOOLEAN := FALSE;
BEGIN
    SELECT NOT EXISTS (SELECT 1 FROM public.profiles) INTO is_first_user;
    meta_name := COALESCE(NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1));
    
    IF is_first_user THEN
        default_role := 'superadmin';
        can_create := TRUE;
        can_edit := TRUE;
        can_delete := TRUE;
        can_roles := TRUE;
        can_audit := TRUE;
        can_export := TRUE;
        can_settings := TRUE;
    ELSE
        IF NEW.raw_user_meta_data->>'role' IS NOT NULL THEN
            BEGIN
                default_role := (NEW.raw_user_meta_data->>'role')::user_role;
            EXCEPTION WHEN OTHERS THEN
                default_role := 'viewer';
            END;
        END IF;

        IF default_role IN ('admin', 'superadmin') THEN
            can_create := TRUE;
            can_edit := TRUE;
            can_delete := (default_role = 'superadmin');
            can_roles := TRUE;
            can_audit := TRUE;
            can_export := TRUE;
            can_settings := (default_role = 'superadmin');
        ELSIF default_role = 'manager' THEN
            can_create := COALESCE((NEW.raw_user_meta_data->>'can_create_users')::boolean, TRUE);
            can_edit := COALESCE((NEW.raw_user_meta_data->>'can_edit_users')::boolean, TRUE);
            can_export := TRUE;
            can_audit := TRUE;
        ELSIF default_role = 'supervisor' THEN
            can_export := TRUE;
        END IF;
    END IF;

    INSERT INTO public.profiles (
        id, email, full_name, role, status,
        can_create_users, can_edit_users, can_delete_users,
        can_manage_roles, can_view_audit_logs, can_export_reports,
        can_manage_system_settings, require_password_change,
        custom_flags, created_by, created_at, updated_at
    ) VALUES (
        NEW.id, NEW.email, meta_name, default_role, 'active',
        can_create, can_edit, can_delete, can_roles, can_audit,
        can_export, can_settings,
        COALESCE((NEW.raw_user_meta_data->>'require_password_change')::boolean, FALSE),
        COALESCE((NEW.raw_user_meta_data->'custom_flags'), '{}'::jsonb),
        (NEW.raw_user_meta_data->>'created_by')::UUID,
        NOW(), NOW()
    );

    INSERT INTO public.audit_logs (
        actor_id, actor_email, action, resource_type, resource_id, details
    ) VALUES (
        COALESCE((NEW.raw_user_meta_data->>'created_by')::UUID, NEW.id),
        COALESCE(NEW.raw_user_meta_data->>'creator_email', NEW.email),
        'USER_REGISTERED', 'profiles', NEW.id::TEXT,
        jsonb_build_object('email', NEW.email, 'role', default_role, 'is_first_user', is_first_user)
    );

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 8. Row Level Security (RLS)
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.departments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Active users can view profiles" ON public.profiles;
CREATE POLICY "Active users can view profiles" ON public.profiles FOR SELECT TO authenticated
USING (auth.uid() = id OR (SELECT status FROM public.profiles WHERE id = auth.uid()) = 'active');

DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
CREATE POLICY "Users can update own profile" ON public.profiles FOR UPDATE TO authenticated
USING (auth.uid() = id);

DROP POLICY IF EXISTS "Admins can manage profiles" ON public.profiles;
CREATE POLICY "Admins can manage profiles" ON public.profiles FOR ALL TO authenticated
USING (public.is_admin_or_superadmin() OR public.has_user_flag('can_edit_users'));

DROP POLICY IF EXISTS "Read departments" ON public.departments;
CREATE POLICY "Read departments" ON public.departments FOR SELECT TO authenticated USING (TRUE);

DROP POLICY IF EXISTS "View audit logs" ON public.audit_logs;
CREATE POLICY "View audit logs" ON public.audit_logs FOR SELECT TO authenticated
USING (public.is_admin_or_superadmin() OR public.has_user_flag('can_view_audit_logs'));

DROP POLICY IF EXISTS "Insert audit logs" ON public.audit_logs;
CREATE POLICY "Insert audit logs" ON public.audit_logs FOR INSERT TO authenticated
WITH CHECK (auth.uid() = actor_id OR actor_id IS NULL);
