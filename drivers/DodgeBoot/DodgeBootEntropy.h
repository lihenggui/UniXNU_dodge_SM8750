// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef DODGE_BOOT_ENTROPY_H
#define DODGE_BOOT_ENTROPY_H

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Rng.h>

#define DODGE_BOOT_ENTROPY_BYTES 256U
#define DODGE_BOOT_ENTROPY_TREE_LIMIT (16U * 1024U * 1024U)

// Volatile stores also erase a partially filled result when the RNG fails.
STATIC VOID
DodgeBootEntropyErase (VOID *Buffer, UINTN Size)
{
  volatile UINT8 *Bytes = (volatile UINT8 *)Buffer;
  while (Size != 0) { *Bytes++ = 0; --Size; }
}

STATIC UINT32
DodgeBootEntropyU32 (CONST UINT8 *Bytes)
{
  return (UINT32)Bytes[0] | ((UINT32)Bytes[1] << 8) |
         ((UINT32)Bytes[2] << 16) | ((UINT32)Bytes[3] << 24);
}

STATIC BOOLEAN
DodgeBootEntropyName (CONST UINT8 *Field, CONST CHAR8 *Name)
{
  UINTN Index;
  for (Index = 0; Index < 32; ++Index) {
    if (Field[Index] != (UINT8)Name[Index]) { return FALSE; }
    if (Name[Index] == 0) { return TRUE; }
  }
  return FALSE;
}

STATIC BOOLEAN
DodgeBootEntropyNode (
  CONST UINT8 *Data, UINTN Size, UINTN *Offset, UINTN Depth,
  BOOLEAN RootParent, UINTN *ChosenCount, UINTN *SeedOffset
  )
{
  UINT32 Properties, Children, Length;
  UINTN Index, Pad, Candidate, NameLength;
  CONST UINT8 *Name;
  BOOLEAN Chosen;

  if ((Depth > 64) || (*Offset > Size) || (Size - *Offset < 8)) { return FALSE; }
  Properties = DodgeBootEntropyU32 (Data + *Offset);
  Children = DodgeBootEntropyU32 (Data + *Offset + 4);
  *Offset += 8;
  if (Properties > (Size - *Offset) / 36) { return FALSE; }
  Candidate = MAX_UINTN;
  Name = NULL;
  NameLength = 0;
  for (Index = 0; Index < Properties; ++Index) {
    CONST UINT8 *Key;
    UINTN Term;
    if (Size - *Offset < 36) { return FALSE; }
    Key = Data + *Offset;
    for (Term = 0; Term < 32 && Key[Term] != 0; ++Term) { }
    if (Term == 32) { return FALSE; }
    Length = DodgeBootEntropyU32 (Key + 32);
    *Offset += 36;
    if (Length > Size - *Offset) { return FALSE; }
    if (DodgeBootEntropyName (Key, "name")) {
      UINTN End;
      if ((Name != NULL) || (Length == 0) || (Length > 256)) { return FALSE; }
      Name = Data + *Offset;
      NameLength = Length;
      for (End = 0; End < Length && Name[End] != 0; ++End) { }
      if (End != Length - 1) { return FALSE; }
    }
    if (DodgeBootEntropyName (Key, "random-seed")) {
      if ((Candidate != MAX_UINTN) || (Length != DODGE_BOOT_ENTROPY_BYTES)) { return FALSE; }
      Candidate = *Offset;
    }
    *Offset += Length;
    Pad = (4 - (Length & 3)) & 3;
    if (Pad > Size - *Offset) { return FALSE; }
    *Offset += Pad;
  }
  if (Name == NULL) { return FALSE; }
  Chosen = Depth == 1 && RootParent && NameLength == 7 &&
           Name[0] == 'c' && Name[1] == 'h' && Name[2] == 'o' &&
           Name[3] == 's' && Name[4] == 'e' && Name[5] == 'n';
  if (Chosen && ++*ChosenCount != 1) { return FALSE; }
  if (Candidate != MAX_UINTN) {
    if (!Chosen || (*SeedOffset != MAX_UINTN)) { return FALSE; }
    *SeedOffset = Candidate;
  }
  if (Children > (Size - *Offset) / 8) { return FALSE; }
  for (Index = 0; Index < Children; ++Index) {
    if (!DodgeBootEntropyNode (Data, Size, Offset, Depth + 1, Depth == 0, ChosenCount, SeedOffset)) { return FALSE; }
  }
  return TRUE;
}

STATIC EFI_STATUS
DodgeBootFindEntropy (CONST VOID *Tree, UINTN TreeSize, UINTN *SeedOffset)
{
  UINTN Offset = 0, ChosenCount = 0, Candidate = MAX_UINTN;
  if (SeedOffset == NULL) { return EFI_INVALID_PARAMETER; }
  *SeedOffset = MAX_UINTN;
  if ((Tree == NULL) || (TreeSize > DODGE_BOOT_ENTROPY_TREE_LIMIT)) { return EFI_INVALID_PARAMETER; }
  if (!DodgeBootEntropyNode (Tree, TreeSize, &Offset, 0, FALSE, &ChosenCount, &Candidate) ||
      (Offset != TreeSize) || (ChosenCount != 1) || (Candidate == MAX_UINTN)) { return EFI_COMPROMISED_DATA; }
  *SeedOffset = Candidate;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
DodgeBootRefreshEntropy (VOID *Tree, UINTN TreeSize, UINTN *SeedOffset)
{
  EFI_RNG_PROTOCOL *Rng = NULL;
  EFI_GUID Raw = EFI_RNG_ALGORITHM_RAW;
  EFI_STATUS Status;
  UINT8 *Seed;
  UINT8 Any;
  UINTN Index;

  Status = DodgeBootFindEntropy (Tree, TreeSize, SeedOffset);
  if (Status != EFI_SUCCESS) { return Status; }
  Seed = (UINT8 *)Tree + *SeedOffset;
  // Never retain the payload's build-time seed, even when discovery fails.
  DodgeBootEntropyErase (Seed, DODGE_BOOT_ENTROPY_BYTES);
  Status = gBS->LocateProtocol (&gEfiRngProtocolGuid, NULL, (VOID **)&Rng);
  if (Status == EFI_SUCCESS && Rng != NULL && Rng->GetRNG != NULL) {
    Status = Rng->GetRNG (Rng, &Raw, DODGE_BOOT_ENTROPY_BYTES, Seed);
  } else if (!EFI_ERROR (Status)) { Status = EFI_DEVICE_ERROR; }
  if (Status != EFI_SUCCESS) {
    DodgeBootEntropyErase (Seed, DODGE_BOOT_ENTROPY_BYTES);
    return EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR;
  }
  Any = 0;
  for (Index = 0; Index < DODGE_BOOT_ENTROPY_BYTES; ++Index) { Any |= Seed[Index]; }
  if (Any == 0) { return EFI_DEVICE_ERROR; }
  // The protocol/provider is responsible for source health. This rejects an
  // absent/all-zero result; it does not estimate or certify physical entropy.
  return EFI_SUCCESS;
}

#endif
