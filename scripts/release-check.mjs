import {spawnSync} from 'node:child_process';
import crypto from 'node:crypto';
const testUrl=process.env.TEST_DATABASE_URL;
if(!testUrl){if(process.env.NODE_ENV==='production')throw new Error('An isolated TEST_DATABASE_URL is required before a production release.');console.log('Release integration checks require an isolated TEST_DATABASE_URL.');process.exit(0)}
if(new URL(testUrl).hostname.replace('-pooler.','.')===new URL(process.env.DATABASE_URL).hostname.replace('-pooler.','.'))throw new Error('Release tests must use a separate database branch.');
const env={...process.env,NODE_ENV:'test',ECM_TEST_MODE:'1',DATABASE_URL:testUrl,ADMIN_EMAIL:'release-'+crypto.randomUUID()+'@example.invalid',ADMIN_PASSWORD:crypto.randomBytes(24).toString('base64url'),JWT_SECRET:crypto.randomBytes(48).toString('hex'),INTEGRATION_ENCRYPTION_KEY:crypto.randomBytes(32).toString('hex'),SMTP_HOST:'',SMTP_USER:'',SMTP_PASSWORD:'',SMTP_FROM:'',GMAIL_RELAY_ACTIVE:'0'};
const result=spawnSync(process.execPath,['--test','--test-concurrency=1','tests/domain.test.cjs','tests/integration.test.cjs'],{env,stdio:'inherit',timeout:240000});
if(result.status!==0)throw new Error('Release verification failed in the isolated test database.');
console.log('Release verification passed. Production startup may continue.');
