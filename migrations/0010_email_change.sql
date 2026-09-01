-- Changing the address on an account.
--
-- There was no way. An agency that moved from one mailbox to another —
-- someone leaving, a domain changing, a shared inbox replacing a personal
-- one — was stuck with the address it signed up with, and the only route
-- out was opening a second account and re-proving ownership of every
-- client domain from scratch.
--
-- Mirrors the confirmation and reset columns above rather than inventing a
-- third shape: hashed token, single use, partial index. The new address
-- lives in `pending_email` until its link is followed, so an unconfirmed
-- change cannot take the account somewhere the holder cannot read.

-- Where the account is going, once the new address proves it can receive.
-- Null whenever no change is in flight.
alter table users add column pending_email text;

-- SHA-256 of the link's token, for the same reason as the other two: a
-- database dump must not hand someone the ability to redirect other
-- people's accounts.
alter table users add column email_change_token_hash text;
alter table users add column email_change_sent_at timestamptz;

create index users_email_change_token_hash_idx
    on users (email_change_token_hash)
    where email_change_token_hash is not null;
