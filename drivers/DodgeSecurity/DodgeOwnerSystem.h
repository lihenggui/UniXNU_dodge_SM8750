// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stddef.h>
#include <stdint.h>

extern "C" bool dodge_owner_system_allowed();
extern "C" size_t dodge_owner_system_identity(uint8_t *, size_t);
extern "C" bool dodge_owner_security_ready();
