-- SPDX-FileCopyrightText: 2026 Latere AI
-- SPDX-License-Identifier: Apache-2.0
--
-- What a person's recovery key unlocks: the backup key it wraps, and a
-- backup key sealed to a new device until that device takes it. Both are
-- ciphertext the server cannot open.

create table recovery (
    person  text primary key,
    wrapped bytea
);

create table transfers (
    person text not null,
    device text not null,
    sealed bytea,
    primary key (person, device)
);
