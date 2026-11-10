// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>

struct DodgeSoftwareRefresh;
extern "C" {
// All operations require the original display work-loop gate. One controller
// may exist at a time. Creation leaves it disabled; the qualified frontend
// must enable/disable it with the logical display's lifecycle.
// Fixed 60 Hz matches the audited original default refresh attributes. This
// timer sends software notifications and does not report a physical vblank.
DodgeSoftwareRefresh *dodge_software_refresh_create(IOService *);
IOReturn dodge_software_refresh_set_enabled(DodgeSoftwareRefresh *,bool);
IOReturn dodge_software_refresh_status(const DodgeSoftwareRefresh *);
// Success consumes the owner reference. A failed event-source removal keeps
// the disabled controller alive so the owner can retry cleanup under the gate.
IOReturn dodge_software_refresh_stop(DodgeSoftwareRefresh *);
// Actual configured software rate, sender invocations and late deadlines.
// Counts record attempts; the original sender does not acknowledge delivery.
extern volatile uint64_t native_gop_vsync[3];
}
