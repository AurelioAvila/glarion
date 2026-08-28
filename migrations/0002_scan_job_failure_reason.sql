-- Why a job ended the way it did. Needed in particular to distinguish "the
-- tool errored" from "we refused to run because verification had lapsed by
-- the time the job was picked up" — the second is a policy outcome we want
-- to be able to show the user and audit, not an anonymous failure.
alter table scan_jobs add column failure_reason text;
