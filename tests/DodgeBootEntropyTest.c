// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "DodgeBootEntropy.h"

_Static_assert(sizeof(EFI_GUID) == 16, "actual EFI GUID ABI");
_Static_assert(sizeof(EFI_STATUS) == 8, "actual EFI status ABI");
_Static_assert(OFFSET_OF(EFI_RNG_PROTOCOL, GetRNG) == 8, "actual RNG function ABI");

EFI_GUID gEfiRngProtocolGuid = EFI_RNG_PROTOCOL_GUID;
static EFI_BOOT_SERVICES Services;
EFI_BOOT_SERVICES *gBS = &Services;
static EFI_RNG_PROTOCOL Rng;
static UINTN LocateCalls, RngCalls, Sequence;
static unsigned Checks, Modes;
enum { Normal, Missing, LocateError, LocateWarning, NullProtocol, NullMethod,
       Unsupported, NotReady, DeviceError, PartialError, RngWarning, AllZero };
static unsigned Mode;

static EFI_STATUS EFIAPI
GetRng(EFI_RNG_PROTOCOL *This, EFI_RNG_ALGORITHM *Algorithm, UINTN Count, UINT8 *Output)
{
  EFI_GUID Raw = EFI_RNG_ALGORITHM_RAW;
  assert(This == &Rng && Algorithm != NULL && memcmp(Algorithm, &Raw, sizeof(Raw)) == 0);
  assert(Count == DODGE_BOOT_ENTROPY_BYTES);
  // The build-time bytes must be gone before calling firmware.
  for (UINTN i = 0; i < Count; ++i) { assert(Output[i] == 0); }
  ++RngCalls; ++Sequence;
  UINTN Filled = Mode == PartialError ? 37 : Count;
  for (UINTN i = 0; i < Filled; ++i) { Output[i] = Mode == AllZero ? 0 : (UINT8)(i + Sequence); }
  switch (Mode) {
    case Unsupported: return EFI_UNSUPPORTED;
    case NotReady: return EFI_NOT_READY;
    case DeviceError: case PartialError: return EFI_DEVICE_ERROR;
    case RngWarning: return EFI_WARN_UNKNOWN_GLYPH;
    default: return EFI_SUCCESS;
  }
}

static EFI_STATUS EFIAPI
Locate(EFI_GUID *Protocol, VOID *Registration, VOID **Interface)
{
  assert(memcmp(Protocol, &gEfiRngProtocolGuid, sizeof(*Protocol)) == 0 && Registration == NULL);
  ++LocateCalls; *Interface = NULL;
  if (Mode == Missing) { return EFI_NOT_FOUND; }
  if (Mode == LocateError) { return EFI_DEVICE_ERROR; }
  if (Mode == LocateWarning) { return EFI_WARN_UNKNOWN_GLYPH; }
  if (Mode != NullProtocol) { Rng.GetRNG = Mode == NullMethod ? NULL : GetRng; *Interface = &Rng; }
  return EFI_SUCCESS;
}

typedef struct { UINT8 Bytes[32768]; UINTN Length, Seed, Chosen; } TREE;
static void U32(TREE *Tree, UINT32 Value)
{
  assert(Tree->Length + 4 <= sizeof(Tree->Bytes));
  for (unsigned i = 0; i < 4; ++i) { Tree->Bytes[Tree->Length++] = (UINT8)(Value >> (i * 8)); }
}
static void Head(TREE *Tree, UINT32 Properties, UINT32 Children) { U32(Tree, Properties); U32(Tree, Children); }
static void Property(TREE *Tree, const char *Name, const void *Bytes, UINT32 Count)
{
  assert(strlen(Name) < 32 && Tree->Length + 36 + Count + 3 <= sizeof(Tree->Bytes));
  memset(Tree->Bytes + Tree->Length, 0, 32); memcpy(Tree->Bytes + Tree->Length, Name, strlen(Name)); Tree->Length += 32;
  U32(Tree, Count);
  if (strcmp(Name, "random-seed") == 0) { Tree->Seed = Tree->Length; }
  memcpy(Tree->Bytes + Tree->Length, Bytes, Count); Tree->Length += Count;
  while (Tree->Length & 3) { Tree->Bytes[Tree->Length++] = 0; }
}
static void Name(TREE *Tree, const char *Value) { Property(Tree, "name", Value, (UINT32)strlen(Value) + 1); }
static TREE Build(unsigned Kind)
{
  TREE Tree = {{0}, 0, MAX_UINTN, 0}; UINT8 Seed[512]; memset(Seed, 0x5c, sizeof(Seed));
  Head(&Tree, 1, Kind == 6 ? 2 : 1); Name(&Tree, "/"); Tree.Chosen = Tree.Length;
  if (Kind == 9) { Head(&Tree, 1, 1); Name(&Tree, "other"); }
  Head(&Tree, Kind == 3 ? 3 : Kind == 4 ? 1 : 2, 0);
  if (Kind != 1) { Name(&Tree, Kind == 5 ? "other" : "chosen"); }
  if (Kind != 4) { Property(&Tree, "random-seed", Seed, Kind == 7 ? 63 : Kind == 8 ? 257 : 256); }
  if (Kind == 1) { Name(&Tree, "chosen"); }
  if (Kind == 3) { Property(&Tree, "random-seed", Seed, 256); }
  if (Kind == 6) { Head(&Tree, 1, 0); Name(&Tree, "chosen"); }
  return Tree;
}
static void Rejected(const UINT8 *Data, UINTN Count)
{
  UINT8 *Guarded = malloc(Count + 128); assert(Guarded != NULL); memset(Guarded, 0xa5, Count + 128);
  memcpy(Guarded + 64, Data, Count); UINTN Offset = 0; LocateCalls = RngCalls = 0;
  EFI_STATUS Result = DodgeBootRefreshEntropy(Guarded + 64, Count, &Offset);
  assert(EFI_ERROR(Result) && Offset == MAX_UINTN && LocateCalls == 0 && RngCalls == 0);
  assert(memcmp(Guarded + 64, Data, Count) == 0);
  for (UINTN i = 0; i < 64; ++i) { assert(Guarded[i] == 0xa5 && Guarded[64 + Count + i] == 0xa5); }
  free(Guarded); ++Checks;
}
static void Provider(TREE *Tree, unsigned Selected)
{
  UINT8 *Guarded = malloc(Tree->Length + 128); assert(Guarded != NULL); memset(Guarded, 0xa5, Tree->Length + 128);
  memcpy(Guarded + 64, Tree->Bytes, Tree->Length); Mode = Selected; LocateCalls = RngCalls = 0; UINTN Offset = 0;
  EFI_STATUS Result = DodgeBootRefreshEntropy(Guarded + 64, Tree->Length, &Offset);
  assert(Offset == Tree->Seed && LocateCalls == 1);
  assert(RngCalls == (UINTN)(Selected == Normal || Selected >= Unsupported));
  assert((Result == EFI_SUCCESS) == (Selected == Normal));
  for (UINTN i = 0; i < Tree->Length; ++i) {
    UINT8 Expected = i >= Offset && i - Offset < 256 ? (Selected == Normal ? (UINT8)(i - Offset + Sequence) : 0) : Tree->Bytes[i];
    assert(Guarded[64 + i] == Expected);
  }
  for (UINTN i = 0; i < 64; ++i) { assert(Guarded[i] == 0xa5 && Guarded[64 + Tree->Length + i] == 0xa5); }
  // Explicitly clear the handoff range on the loader's later failure path.
  DodgeBootEntropyErase(Guarded + 64 + Offset, 256);
  for (UINTN i = 0; i < 256; ++i) { assert(Guarded[64 + Offset + i] == 0); }
  free(Guarded); ++Modes;
}
int main(int argc, char **argv)
{
  Services.LocateProtocol = Locate;
  TREE Good = Build(0), Reordered = Build(1);
  for (unsigned i = Normal; i <= AllZero; ++i) { Provider(&Good, i); }
  Provider(&Good, Normal); Provider(&Reordered, Normal); // Each attempt obtains a fresh result; no cached seed.
  for (unsigned Kind = 3; Kind <= 9; ++Kind) { TREE Bad = Build(Kind); Rejected(Bad.Bytes, Bad.Length); }
  for (UINTN End = 0; End < Good.Length; ++End) { Rejected(Good.Bytes, End); }
  UINT8 Extra[sizeof(Good.Bytes)]; memcpy(Extra, Good.Bytes, Good.Length); Extra[Good.Length] = 0;
  Rejected(Extra, Good.Length + 1);
  const UINTN Fields[] = {0, 4, 40, Good.Chosen, Good.Chosen + 4, Good.Seed - 4};
  for (UINTN i = 0; i < sizeof(Fields) / sizeof(*Fields); ++i) {
    TREE Bad = Good; memset(Bad.Bytes + Fields[i], 0xff, 4); Rejected(Bad.Bytes, Bad.Length);
  }
  TREE NoTerm = Good; memset(NoTerm.Bytes + 8, 'x', 32); Rejected(NoTerm.Bytes, NoTerm.Length);
  TREE Depth = {{0}, 0, MAX_UINTN, 0};
  for (unsigned i = 0; i < 66; ++i) { Head(&Depth, 1, 1); Name(&Depth, "node"); }
  Head(&Depth, 1, 0); Name(&Depth, "leaf"); Rejected(Depth.Bytes, Depth.Length);
  UINTN Offset = 0;
  assert(DodgeBootRefreshEntropy(NULL, 0, &Offset) == EFI_INVALID_PARAMETER && Offset == MAX_UINTN);
  assert(DodgeBootRefreshEntropy(Good.Bytes, Good.Length, NULL) == EFI_INVALID_PARAMETER);
  assert(DodgeBootRefreshEntropy(Good.Bytes, DODGE_BOOT_ENTROPY_TREE_LIMIT + 1, &Offset) == EFI_INVALID_PARAMETER);
  for (int i = 1; i < argc; ++i) {
    FILE *File = fopen(argv[i], "rb"); assert(File != NULL && fseek(File, 0, SEEK_END) == 0);
    long Count = ftell(File); assert(Count > 0 && Count <= DODGE_BOOT_ENTROPY_TREE_LIMIT && fseek(File, 0, SEEK_SET) == 0);
    UINT8 *Data = malloc((size_t)Count); assert(Data != NULL && fread(Data, 1, (size_t)Count, File) == (size_t)Count); fclose(File);
    Mode = Normal; LocateCalls = RngCalls = 0; assert(DodgeBootRefreshEntropy(Data, (UINTN)Count, &Offset) == EFI_SUCCESS);
    assert(LocateCalls == 1 && RngCalls == 1); DodgeBootEntropyErase(Data + Offset, 256); free(Data);
    puts("PASS: actual private ADT accepted and refreshed using the explicit RNG peer");
  }
  printf("PASS: %u provider/order cases, %u malformed/truncation cases and three invalid parameters; no firmware entropy qualification\n", Modes, Checks);
  return 0;
}
