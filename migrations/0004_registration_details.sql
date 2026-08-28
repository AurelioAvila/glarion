-- Fuller registration, and email confirmation before an account works.

alter table users add column first_name text;
alter table users add column last_name text;

-- Collected to check the account holder is old enough to enter a paid
-- contract. That check is the reason the column exists; without a purpose
-- it would just be personal data we hold for nothing.
alter table users add column date_of_birth date;

-- Null until the address is confirmed. Sign-in refuses while it is null, so
-- an unconfirmed address cannot be used to reach anything.
alter table users add column email_verified_at timestamptz;

-- The confirmation link's token, stored as a SHA-256 hash. A database dump
-- should not hand someone the ability to confirm other people's addresses,
-- and we never need the original back — only to compare against what
-- arrives in the link.
alter table users add column verification_token_hash text;
alter table users add column verification_sent_at timestamptz;

create index users_verification_token_hash_idx
    on users (verification_token_hash)
    where verification_token_hash is not null;

-- Accounts that already existed predate confirmation and would otherwise be
-- locked out by the new sign-in rule.
update users set email_verified_at = created_at where email_verified_at is null;
