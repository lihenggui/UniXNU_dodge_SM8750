// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOTypes.h>
class OSMetaClass;
extern "C" IOReturn dodge_hid_edge_prepare();
extern "C" unsigned dodge_hid_edge_driver_bytes();
extern "C" const OSMetaClass *dodge_hid_edge_driver_meta();
extern "C" bool dodge_hid_edge_instance_pinned();
