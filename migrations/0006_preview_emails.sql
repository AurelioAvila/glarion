-- Rate limiting for the free emailed report.
--
-- Sending a message to an address somebody typed in is a mail-bombing
-- primitive unless the *recipient* is protected, not just the sender's IP:
-- one address can otherwise be targeted from many addresses.
--
-- The address is stored as a hash. We need to recognise it to enforce the
-- cooldown and nothing else, so keeping the plaintext would be holding
-- personal data for no purpose we could name.
create table preview_email_sends (
    email_hash text primary key,
    last_sent_at timestamptz not null default now(),
    -- How many have gone to this address in total. A count that keeps
    -- climbing is the signature of somebody being targeted rather than
    -- somebody using the product.
    send_count integer not null default 1
);

create index preview_email_sends_last_sent_idx on preview_email_sends (last_sent_at);
