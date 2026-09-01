-- Password recovery.
--
-- There was none. An account whose password was forgotten was gone: no
-- endpoint existed to start a reset, so the only route back in was for the
-- person who runs the database to change the row by hand. For something sold
-- on a subscription that is not a missing convenience, it is a way to lose a
-- paying customer permanently and silently.
--
-- Deliberately mirrors the email-confirmation columns above rather than
-- inventing a second shape: same hashing, same single-use trick, same
-- partial index. One pattern to reason about, not two.

-- The reset link's token, stored as a SHA-256 hash for the same reason the
-- confirmation token is: a database dump must not hand someone the ability
-- to take over other people's accounts, and the original is never needed
-- back — only compared against what arrives in the link.
alter table users add column password_reset_token_hash text;
alter table users add column password_reset_sent_at timestamptz;

create index users_password_reset_token_hash_idx
    on users (password_reset_token_hash)
    where password_reset_token_hash is not null;
