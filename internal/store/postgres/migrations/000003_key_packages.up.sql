-- SPDX-FileCopyrightText: 2026 Latere AI
-- SPDX-License-Identifier: Apache-2.0
--
-- Each device's key packages: one-time ones, handed out oldest first and
-- deleted as they go, and at most one last resort, kept when handed out
-- and replaced by the next. ord is the order they were published in,
-- which is what oldest means: two published in one call share a time.

create table key_packages (
    ord         bigint generated always as identity primary key,
    person      text        not null,
    device      text        not null,
    ref         text        not null,
    data        bytea,
    last_resort boolean     not null,
    created     timestamptz not null
);
create index key_packages_device on key_packages (person, device, last_resort, ord);
create unique index key_packages_last_resort on key_packages (person, device) where last_resort;
