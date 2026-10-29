-- SPDX-FileCopyrightText: 2026 Latere AI
-- SPDX-License-Identifier: Apache-2.0
--
-- Each conversation with its group's public state, its ordered log, and
-- the welcomes its commits filed. Messages and welcomes are ciphertext;
-- the server reads the state it checks commits against and nothing else.

-- conversations is the state at the current epoch. seq is the last
-- message's number and version counts the changes to view: an append
-- names the version it read, and one that no longer stands changes
-- nothing. members is each device's spans of the log, as a json array.
-- An epoch is an unsigned 64-bit number, which bigint cannot hold whole.
-- The id sorts byte by byte, as Go compares strings, so a page that
-- starts after an id is the page a caller expects.
create table conversations (
    id         text           collate "C" primary key,
    kind       smallint       not null,
    level      smallint       not null,
    people     text[]         not null,
    owners     text[]         not null,
    epoch      numeric(20, 0) not null,
    seq        bigint         not null,
    version    bigint         not null,
    view       bytea,
    group_info bytea,
    members    jsonb          not null,
    created    timestamptz    not null,
    updated    timestamptz    not null
);
create index conversations_people on conversations using gin (people);

-- messages is the log. A deleted message's number is never taken again,
-- because the next one comes from the conversation's seq.
create table messages (
    conversation text           collate "C" not null references conversations (id),
    seq          bigint         not null,
    epoch        numeric(20, 0) not null,
    kind         text           not null,
    data         bytea,
    person       text           not null,
    device       text           not null,
    created      timestamptz    not null,
    primary key (conversation, seq)
);
create index messages_created on messages (created);

-- welcomes are filed for the devices a commit added, and ord is the order
-- they were filed in.
create table welcomes (
    ord          bigint      generated always as identity primary key,
    id           text        not null,
    person       text        not null,
    device       text        not null,
    conversation text        collate "C" not null references conversations (id),
    seq          bigint      not null,
    data         bytea,
    notice       bytea,
    created      timestamptz not null
);
create index welcomes_device on welcomes (person, device, ord);
create index welcomes_created on welcomes (created);
