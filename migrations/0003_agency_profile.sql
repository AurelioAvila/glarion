-- White-label identity.
--
-- The product is sold to agencies who forward reports to their own clients,
-- so a report carries the agency's name, not ours. That identity belongs to
-- the account; which client a given site belongs to belongs to the target,
-- because one agency has many clients.

alter table users add column agency_name text;
alter table users add column agency_logo_url text;

alter table targets add column client_name text;
