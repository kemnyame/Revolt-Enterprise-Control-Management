import type {Pool} from 'pg';
import {notificationSchema} from './commercial-notifications';
export const commercialSchema=`
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS temporary_password_expires timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version integer NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN IF NOT EXISTS platform_admin boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notify_email boolean NOT NULL DEFAULT true;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS subscription_plan text NOT NULL DEFAULT 'Professional';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS subscription_expires date;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS notifications_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE controls ADD COLUMN IF NOT EXISTS testing_criteria text NOT NULL DEFAULT '';
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS is_sample boolean NOT NULL DEFAULT false;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS is_sample boolean NOT NULL DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_sample boolean NOT NULL DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS owner_user_id integer REFERENCES users(id);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS root_cause text NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS recommendation text NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS completion_notes text NOT NULL DEFAULT '';
CREATE SEQUENCE IF NOT EXISTS ecm_reference_seq;
CREATE TABLE IF NOT EXISTS ecm_records(
 id bigserial PRIMARY KEY,organization_id integer NOT NULL REFERENCES organizations(id),module text NOT NULL,
 reference text NOT NULL,title text NOT NULL,description text NOT NULL DEFAULT '',owner_id integer NOT NULL REFERENCES users(id),
 reviewer_id integer REFERENCES users(id),priority text NOT NULL,status text NOT NULL,due_date date,details jsonb NOT NULL DEFAULT '{}',
 parent_id bigint REFERENCES ecm_records(id),asset_id bigint REFERENCES ecm_records(id),control_id integer REFERENCES controls(id),finding_id integer REFERENCES findings(id),
 version integer NOT NULL DEFAULT 1,is_sample boolean NOT NULL DEFAULT false,source_key text,
 created_by integer NOT NULL REFERENCES users(id),updated_by integer NOT NULL REFERENCES users(id),
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),archived_at timestamptz,
 UNIQUE(organization_id,reference),UNIQUE(organization_id,source_key),CHECK(parent_id IS NULL OR parent_id<>id),
 CHECK(module IN ('plans','risks','reviews','slas','assets','licences','changes','actions'))
);
CREATE INDEX IF NOT EXISTS ecm_records_scope ON ecm_records(organization_id,module,status,due_date);
CREATE UNIQUE INDEX IF NOT EXISTS ecm_licence_match ON ecm_records(organization_id,lower(title),lower(coalesce(details->>'vendor','')),lower(coalesce(details->>'licence_type','')),lower(coalesce(details->>'department',''))) WHERE module='licences' AND archived_at IS NULL;
CREATE INDEX IF NOT EXISTS ecm_records_owner ON ecm_records(organization_id,owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS ecm_asset_tag ON ecm_records(organization_id,lower(details->>'asset_tag')) WHERE module='assets' AND archived_at IS NULL;
CREATE TABLE IF NOT EXISTS ecm_events(
 id bigserial PRIMARY KEY,organization_id integer NOT NULL REFERENCES organizations(id),record_id bigint REFERENCES ecm_records(id),
 actor_id integer NOT NULL REFERENCES users(id),action text NOT NULL,note text NOT NULL DEFAULT '',before_data jsonb,after_data jsonb,created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ecm_events_record ON ecm_events(organization_id,record_id,id);
CREATE OR REPLACE FUNCTION ecm_history_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Commercial decision history is append-only'; END $$;
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='ecm_events_immutable') THEN CREATE TRIGGER ecm_events_immutable BEFORE UPDATE OR DELETE ON ecm_events FOR EACH ROW EXECUTE FUNCTION ecm_history_immutable(); END IF; END $$;
CREATE TABLE IF NOT EXISTS ecm_renewals(
 id bigserial PRIMARY KEY,organization_id integer NOT NULL REFERENCES organizations(id),licence_id bigint NOT NULL REFERENCES ecm_records(id),previous_expiry date,next_expiry date NOT NULL,payment_date date,payment_minor bigint,notes text NOT NULL DEFAULT '',actor_id integer NOT NULL REFERENCES users(id),source_key text,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(organization_id,source_key)
);
CREATE TABLE IF NOT EXISTS ecm_receipts(
 organization_id integer NOT NULL REFERENCES organizations(id),request_id text NOT NULL,actor_id integer NOT NULL REFERENCES users(id),operation text NOT NULL,payload_hash text NOT NULL,result jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(organization_id,request_id)
);
CREATE TABLE IF NOT EXISTS ecm_email_queue(
 id bigserial PRIMARY KEY,organization_id integer NOT NULL REFERENCES organizations(id),recipient text NOT NULL,subject text NOT NULL,body text NOT NULL,
 category text NOT NULL,dedupe_key text NOT NULL UNIQUE,status text NOT NULL DEFAULT 'queued',provider_id text,error text,
 created_at timestamptz NOT NULL DEFAULT now(),claimed_at timestamptz,submitted_at timestamptz,claim_token text,expires_at timestamptz
);
CREATE INDEX IF NOT EXISTS ecm_email_dispatch ON ecm_email_queue(status,created_at);
CREATE TABLE IF NOT EXISTS ecm_password_resets(
 token_hash text PRIMARY KEY,user_id integer NOT NULL REFERENCES users(id),expires_at timestamptz NOT NULL,used_at timestamptz,created_at timestamptz NOT NULL DEFAULT now()
);
`;
export async function migrateCommercial(pool:Pool){const client=await pool.connect();try{await client.query('BEGIN');await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ecm-commercial-schema-v2',0))");await client.query(commercialSchema);await client.query(notificationSchema);await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}
