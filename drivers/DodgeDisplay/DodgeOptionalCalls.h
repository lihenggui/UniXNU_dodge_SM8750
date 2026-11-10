// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
// The caller must first test a weak function for presence. Force an indirect
// call so a static ARM64 kernel can represent an absent weak import as address
// zero without emitting a +/-128MiB direct branch to that address.
// This supplies no implementation, return value or fallback for the function.
template<typename Function,typename... Arguments>
__attribute__((always_inline)) inline auto dodge_optional_call(Function function,Arguments... arguments)
    -> decltype(function(arguments...)) {
    Function volatile indirect=function;
    return indirect(arguments...);
}
