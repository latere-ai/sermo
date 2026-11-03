-- SPDX-FileCopyrightText: 2026 Latere AI
-- SPDX-License-Identifier: Apache-2.0
--
-- Each person's history backup: one sealed record for each message of a
-- conversation, under a key only the person's devices hold. The server
-- keeps ciphertext, the id the devices derived and the order it stored
-- them in. The retention sweep does not touch these.

-- backup_records is keyed by person first: two people of one conversation
-- have different keys and so different records. seq is the order the
-- records were stored in, which a reader pages by.
create table backup_records (
    person       text        collate "C" not null,
    conversation text        collate "C" not null,
    id           text        collate "C" not null,
    seq          bigint      generated always as identity,
    sealed       bytea       not null,
    created      timestamptz not null,
    primary key (person, conversation, id)
);
create unique index backup_records_seq on backup_records (person, conversation, seq);

-- backup_usage is the bytes each person's records hold, kept with them so
-- a write checks a limit without adding the records up.
create table backup_usage (
    person text   collate "C" primary key,
    bytes  bigint not null
);
