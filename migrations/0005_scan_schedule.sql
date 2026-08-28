-- Recurring scans.
--
-- Manual scanning makes this a tool somebody remembers to use. A schedule
-- is what an agency sells to its client — "we watch your site" — and it is
-- what makes the scan history on the dashboard mean anything.

alter table targets add column scan_cadence text not null default 'manual'
    check (scan_cadence in ('manual', 'weekly', 'monthly'));

-- When a scan was last queued *by the scheduler*, which is not the same as
-- when the target was last scanned: a manual scan should not push back the
-- next scheduled one, or a customer clicking the button would quietly
-- disable the monitoring they are paying for.
alter table targets add column last_scheduled_at timestamptz;

-- Who asked for a scan: a person at the time, or a standing instruction
-- they set up earlier. Both are authorization, and the audit trail has to
-- be able to say which.
alter table scan_authorizations add column source text not null default 'manual'
    check (source in ('manual', 'schedule'));

create index targets_scan_cadence_idx on targets (scan_cadence)
    where scan_cadence <> 'manual';
