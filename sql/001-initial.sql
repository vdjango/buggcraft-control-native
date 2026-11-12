BEGIN;
SELECT pg_advisory_xact_lock(820641091);
CREATE TABLE IF NOT EXISTS schema_version(version integer PRIMARY KEY);
INSERT INTO schema_version VALUES(1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS enrollment_credentials(
 id text PRIMARY KEY, digest text UNIQUE NOT NULL, pool text NOT NULL,
 enabled boolean NOT NULL DEFAULT true, quota integer CHECK(quota > 0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS challenges(
 id text PRIMARY KEY, kind text NOT NULL, public_key text NOT NULL,
 credential_id text REFERENCES enrollment_credentials(id), payload jsonb NOT NULL,
 message text NOT NULL, expires_at timestamptz NOT NULL, used boolean NOT NULL DEFAULT false, result_epoch text);
CREATE INDEX IF NOT EXISTS challenges_expiry ON challenges(expires_at);
CREATE TABLE IF NOT EXISTS identities(
 id text PRIMARY KEY, public_key text NOT NULL, username text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX IF NOT EXISTS identity_name ON identities(lower(username));
CREATE TABLE IF NOT EXISTS devices(
 account_id text REFERENCES identities(id), id text NOT NULL, epoch text NOT NULL,
 revoked boolean NOT NULL DEFAULT false, PRIMARY KEY(account_id,id));
ALTER TABLE devices ADD COLUMN IF NOT EXISTS delegation_digest text;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS valid_until timestamptz;
CREATE TABLE IF NOT EXISTS nodes(
 id text PRIMARY KEY, public_key text UNIQUE NOT NULL, credential_id text REFERENCES enrollment_credentials(id),
 pool text NOT NULL, region text NOT NULL, operator text NOT NULL, endpoint text NOT NULL,
 epoch text NOT NULL, shard integer NOT NULL DEFAULT 0 CHECK(shard BETWEEN 0 AND 63),
 status text NOT NULL DEFAULT 'probing' CHECK(status IN('probing','active','draining','revoked')),
 slots integer NOT NULL CHECK(slots BETWEEN 1 AND 100000), bandwidth bigint NOT NULL CHECK(bandwidth>0),
 observed_slots integer NOT NULL DEFAULT 0 CHECK(observed_slots>=0), observed_bandwidth bigint NOT NULL DEFAULT 0,
 sequence bigint NOT NULL DEFAULT 0, health_until timestamptz NOT NULL DEFAULT clock_timestamp(),
 heartbeat jsonb NOT NULL DEFAULT '{}', version bigint NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS nodes_candidates ON nodes(pool,region,shard,status,health_until);
CREATE INDEX IF NOT EXISTS nodes_route_cursor ON nodes(pool,region,shard,id) WHERE status='active';
CREATE TABLE IF NOT EXISTS reservations(
 id text PRIMARY KEY, actor text REFERENCES identities(id), idem text NOT NULL, digest text NOT NULL,
 node_id text REFERENCES nodes(id), room_id text NOT NULL, room_epoch bigint NOT NULL,
 slots integer NOT NULL CHECK(slots>0), bandwidth bigint NOT NULL CHECK(bandwidth>0),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','active','released')),
 expires_at timestamptz NOT NULL, ticket text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(actor,idem));
CREATE INDEX IF NOT EXISTS reservation_capacity ON reservations(node_id,state,expires_at);
CREATE TABLE IF NOT EXISTS rooms(
 id text PRIMARY KEY, owner_account text REFERENCES identities(id), node_id text REFERENCES nodes(id),
 epoch bigint NOT NULL CHECK(epoch>0), reservation_id text REFERENCES reservations(id),
 state text NOT NULL DEFAULT 'open' CHECK(state IN('open','closed')));
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS listing jsonb;
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS secret text;
CREATE TABLE IF NOT EXISTS sessions(
 id text PRIMARY KEY, account_id text REFERENCES identities(id), device_id text NOT NULL, epoch text NOT NULL,
 idem text NOT NULL, sequence bigint NOT NULL DEFAULT 0,
 state text NOT NULL DEFAULT 'online' CHECK(state IN('online','offline')),
 expires_at timestamptz NOT NULL, UNIQUE(account_id,device_id,idem));
CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_id,expires_at);
CREATE TABLE IF NOT EXISTS friendships(
 low_id text REFERENCES identities(id), high_id text REFERENCES identities(id),
 requested_by text NOT NULL, state text NOT NULL CHECK(state IN('pending','accepted','rejected')),
 PRIMARY KEY(low_id,high_id), CHECK(low_id < high_id));
CREATE TABLE IF NOT EXISTS social_events(
 cursor bigserial UNIQUE NOT NULL, actor text REFERENCES identities(id), event_id text NOT NULL,
 target text REFERENCES identities(id), device_id text NOT NULL, kind text NOT NULL,
 digest text NOT NULL, body jsonb NOT NULL, expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(actor,event_id));
CREATE INDEX IF NOT EXISTS social_inbox ON social_events(target,cursor,expires_at);
CREATE INDEX IF NOT EXISTS social_expiry ON social_events(expires_at);
CREATE TABLE IF NOT EXISTS outbox(
 cursor bigint PRIMARY KEY REFERENCES social_events(cursor), target text NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_receipts(
 cursor bigint REFERENCES social_events(cursor), account_id text NOT NULL, device_id text NOT NULL,
 delivered boolean NOT NULL DEFAULT false, seen boolean NOT NULL DEFAULT false,
 PRIMARY KEY(cursor,account_id,device_id));
CREATE TABLE IF NOT EXISTS rate_buckets(
 key text PRIMARY KEY, window_id bigint NOT NULL, count integer NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
 cursor bigserial PRIMARY KEY, action text NOT NULL, subject text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS feedback(
 id text PRIMARY KEY, digest text NOT NULL, message text NOT NULL, contact text NOT NULL,
 diagnostics jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX IF NOT EXISTS feedback_created ON feedback(created_at);
-- Browser identity preserves the existing encrypted record and device protocol.
-- It is distinct from player routing identities and never stores plaintext passwords.
CREATE TABLE IF NOT EXISTS browser_accounts(
 id text PRIMARY KEY, username text NOT NULL, record jsonb NOT NULL,
 blocked boolean NOT NULL DEFAULT false);
CREATE INDEX IF NOT EXISTS browser_username ON browser_accounts(lower(username));
CREATE TABLE IF NOT EXISTS browser_devices(
 id text PRIMARY KEY, account_id text NOT NULL REFERENCES browser_accounts(id), body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS browser_account_devices ON browser_devices(account_id);
CREATE TABLE IF NOT EXISTS browser_values(
 kind text NOT NULL, id text NOT NULL, body jsonb NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(kind,id));
CREATE INDEX IF NOT EXISTS browser_values_expiry ON browser_values(expires_at);
CREATE INDEX IF NOT EXISTS browser_sessions_account ON browser_values((body->>'account')) WHERE kind='session';
CREATE TABLE IF NOT EXISTS browser_mailboxes(
 mailbox text NOT NULL, account_id text NOT NULL REFERENCES browser_accounts(id),
 preferred boolean NOT NULL DEFAULT false, PRIMARY KEY(mailbox,account_id));
CREATE TABLE IF NOT EXISTS legacy_social_import(
 digest text PRIMARY KEY, body jsonb NOT NULL, imported_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS account_activity(
 account_id text REFERENCES identities(id), kind text CHECK(kind IN('online','multiplayer')),
 started bigint NOT NULL, last_seen bigint NOT NULL, lease_until bigint NOT NULL,
 seconds bigint NOT NULL DEFAULT 0 CHECK(seconds>=0), PRIMARY KEY(account_id,kind));
CREATE TABLE IF NOT EXISTS account_activity_days(
 account_id text REFERENCES identities(id), kind text NOT NULL, day date NOT NULL,
 seconds bigint NOT NULL CHECK(seconds>=0), PRIMARY KEY(account_id,kind,day));
CREATE INDEX IF NOT EXISTS activity_days_retention ON account_activity_days(day);
CREATE TABLE IF NOT EXISTS companion_activity(
 low_id text REFERENCES identities(id), high_id text REFERENCES identities(id),
 started bigint NOT NULL,last_seen bigint NOT NULL,seconds bigint NOT NULL DEFAULT 0,
 room_id text NOT NULL DEFAULT '',room_epoch bigint NOT NULL DEFAULT 0,lease_until bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(low_id,high_id), CHECK(low_id<high_id));
ALTER TABLE companion_activity ADD COLUMN IF NOT EXISTS room_id text NOT NULL DEFAULT '';
ALTER TABLE companion_activity ADD COLUMN IF NOT EXISTS room_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE companion_activity ADD COLUMN IF NOT EXISTS lease_until bigint NOT NULL DEFAULT 0;
COMMIT;
