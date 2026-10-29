-- SPDX-FileCopyrightText: 2026 Latere AI
-- SPDX-License-Identifier: Apache-2.0
--
-- The directory: each person's records and the revocations of their keys.
-- A record holds public keys and signatures; no private key reaches a row.

-- devices is one row per record of a person, a device's or a recovery
-- key's, replaced whole when it is put again. The id sorts byte by byte,
-- as Go compares strings, whatever collation the database was made with.
create table devices (
    person         text     not null,
    id             text     collate "C" not null,
    kind           smallint not null,
    signature_key  bytea,
    encryption_key bytea,
    voucher        text     not null,
    voucher_key    bytea,
    vouch          bytea,
    possession     bytea,
    primary key (person, id)
);

-- revocations keeps each revocation once per person, by its signature,
-- and ord is the order they were first added in.
create table revocations (
    ord       bigint generated always as identity primary key,
    person    text  not null,
    key       bytea,
    keep      bytea[],
    signed_by text  not null,
    signature bytea not null,
    unique (person, signature)
);
create index revocations_person on revocations (person, ord);
