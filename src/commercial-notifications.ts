import type {Pool} from 'pg';
import nodemailer from 'nodemailer';

export const notificationSchema=`
CREATE TABLE IF NOT EXISTS ecm_reminder_events(
 organization_id integer NOT NULL REFERENCES organizations(id),record_id bigint NOT NULL REFERENCES ecm_records(id),due_date date NOT NULL,bucket text NOT NULL,recipient text NOT NULL,queue_id bigint NOT NULL REFERENCES ecm_email_queue(id),created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(organization_id,record_id,due_date,bucket,recipient)
);
CREATE OR REPLACE FUNCTION ecm_prepare_notifications() RETURNS integer LANGUAGE plpgsql AS $$
DECLARE person record; items jsonb; entry jsonb; queue bigint; sent integer:=0; body_text text;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('ecm-notification-preparation-v1',0));
 FOR person IN SELECT DISTINCT u.id,u.organization_id,u.email,u.name,o.name organization_name FROM users u JOIN organizations o ON o.id=u.organization_id WHERE u.status='active' AND u.notify_email AND o.status='active' AND o.notifications_enabled AND u.email !~* '\\.(invalid|test|demo|local)$' LOOP
  SELECT jsonb_agg(jsonb_build_object('id',d.id,'reference',d.reference,'title',d.title,'due',d.due_date,'module',d.module,'bucket',d.bucket) ORDER BY d.due_date,d.id) INTO items
  FROM (
   SELECT r.*,CASE WHEN r.due_date<current_date THEN 'overdue-'||floor((current_date-r.due_date)::numeric/7)::text WHEN r.due_date=current_date THEN 'days-0' WHEN r.due_date-current_date<=1 THEN 'days-1' WHEN r.due_date-current_date<=7 THEN 'days-7' WHEN r.due_date-current_date<=14 THEN 'days-14' WHEN r.due_date-current_date<=30 THEN 'days-30' ELSE 'two-months' END bucket
   FROM ecm_records r WHERE r.organization_id=person.organization_id AND r.owner_id=person.id AND NOT r.is_sample AND r.archived_at IS NULL AND r.status NOT IN ('Closed','Completed','Retired','Cancelled','Inactive') AND r.due_date IS NOT NULL
    AND ((r.module='licences' AND current_date>=(r.due_date-interval '2 months')::date) OR (r.module='slas' AND current_date>=r.due_date-greatest(7,least(365,coalesce(nullif(r.details->>'notice_days','')::int,30)))) OR (r.module NOT IN ('licences','slas','assets') AND r.due_date<=current_date+7))
  ) d WHERE NOT EXISTS(SELECT 1 FROM ecm_reminder_events x WHERE x.organization_id=person.organization_id AND x.record_id=d.id AND x.due_date=d.due_date AND x.bucket=d.bucket AND x.recipient=person.email);
  IF items IS NOT NULL THEN
   SELECT 'Hello '||person.name||E',\\n\\nThe following items need attention in '||person.organization_name||E':\\n\\n'||string_agg((e->>'reference')||' | '||(e->>'title')||' | Due: '||(e->>'due'),E'\\n')||E'\\n\\nOpen your private workspace: https://revolt-enterprise-control-management.onrender.com\\n\\nThis is an automated operational reminder.' INTO body_text FROM jsonb_array_elements(items) e;
   INSERT INTO ecm_email_queue(organization_id,recipient,subject,body,category,dedupe_key) VALUES(person.organization_id,person.email,'IT Control reminders: '||person.organization_name,body_text,'reminder','digest:'||person.organization_id||':'||person.id||':'||md5(items::text)) ON CONFLICT(dedupe_key) DO NOTHING RETURNING id INTO queue;
   IF queue IS NOT NULL THEN
    FOR entry IN SELECT * FROM jsonb_array_elements(items) LOOP INSERT INTO ecm_reminder_events(organization_id,record_id,due_date,bucket,recipient,queue_id) VALUES(person.organization_id,(entry->>'id')::bigint,(entry->>'due')::date,entry->>'bucket',person.email,queue) ON CONFLICT DO NOTHING; END LOOP;
    sent:=sent+1;
   END IF;
  END IF;
 END LOOP;
 RETURN sent;
END $$;
CREATE OR REPLACE FUNCTION ecm_claim_emails(batch_size integer DEFAULT 10) RETURNS TABLE(id bigint,organization_id integer,recipient text,subject text,body text,claim_token text) LANGUAGE plpgsql AS $$
BEGIN
 UPDATE ecm_email_queue q SET status='needs_review',error='Delivery outcome uncertain; check the provider before retrying.' WHERE q.status='dispatching' AND q.claimed_at<now()-interval '20 minutes';
 UPDATE ecm_email_queue q SET status='expired',body='',error='The message expired before submission.' WHERE q.status='queued' AND q.expires_at IS NOT NULL AND q.expires_at<now();
 RETURN QUERY WITH candidates AS (
  SELECT q.id FROM ecm_email_queue q JOIN organizations o ON o.id=q.organization_id WHERE q.status='queued' AND (o.notifications_enabled OR q.category IN ('welcome','password_reset')) AND o.status='active' AND (q.expires_at IS NULL OR q.expires_at>now()) AND EXISTS(SELECT 1 FROM users u WHERE u.organization_id=q.organization_id AND lower(u.email)=lower(q.recipient) AND u.status='active' AND (u.notify_email OR q.category IN ('welcome','password_reset'))) ORDER BY q.id FOR UPDATE OF q SKIP LOCKED LIMIT least(greatest(batch_size,1),50)
 ) UPDATE ecm_email_queue q SET status='dispatching',claimed_at=now(),claim_token=md5(random()::text||clock_timestamp()::text||q.id::text) FROM candidates c WHERE q.id=c.id RETURNING q.id,q.organization_id,q.recipient,q.subject,q.body,q.claim_token;
END $$;
CREATE OR REPLACE FUNCTION ecm_ack_email(message_id bigint,claim text,provider_message_id text) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE changed integer;
BEGIN IF coalesce(provider_message_id,'')='' THEN RAISE EXCEPTION 'Provider message ID is required'; END IF;
 UPDATE ecm_email_queue SET status='submitted',provider_id=provider_message_id,submitted_at=now(),body='',error=NULL WHERE id=message_id AND claim_token=claim AND status='dispatching';GET DIAGNOSTICS changed=ROW_COUNT;RETURN changed=1;END $$;
`;

// Optional immediate SMTP transport. Gmail relay remains available without copying OAuth tokens into the app.
export async function dispatchSmtp(pool:Pool){
 if(!process.env.SMTP_HOST||!process.env.SMTP_USER||!process.env.SMTP_PASSWORD||!process.env.SMTP_FROM)return {configured:false,submitted:0};
 const transport=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:process.env.SMTP_PORT==='465',auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASSWORD},connectionTimeout:10000,socketTimeout:15000});
 const q=await pool.query('SELECT * FROM ecm_claim_emails(10)');let submitted=0;
 for(const row of q.rows){try{const info=await transport.sendMail({from:process.env.SMTP_FROM,to:row.recipient,subject:row.subject,text:row.body,messageId:`<ecm-${row.id}@revolt-control.local>`});await pool.query('SELECT ecm_ack_email($1,$2,$3)',[row.id,row.claim_token,info.messageId]);submitted++}catch(e){await pool.query("UPDATE ecm_email_queue SET status='needs_review',error='SMTP submission failed or was uncertain; check provider logs before retrying.' WHERE id=$1 AND claim_token=$2",[row.id,row.claim_token])}}
 transport.close();return {configured:true,submitted};
}
