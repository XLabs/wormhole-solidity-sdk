// SPDX-License-Identifier: Apache 2
pragma solidity ^0.8.14;

import {BytesParsing} from "wormhole-sdk/libraries/BytesParsing.sol";
import {VaaLib, GuardianSignature} from "wormhole-sdk/libraries/VaaLib.sol";

/*

VaaLib2 is a library for reading and writing Wormhole VAAs. It re-exports several functions from
VaaLib, but adds some additional functionality to support new VAA versions and batching.

It supports the following VAA versions:
- V1, Multisig
- V2, Schnorr
- V3, ECDSA

======== Decoding ========

It supports decoding VAAs using a three step process:
1. Decode the version, which tells us which header to decode
   - decodeVaaHeaderVersion{Cd,Mem}
2. Decode the header based on the version
   - decodeVaaHeader{Multisig,Schnorr,ECDSA}{Cd,Mem}
3. Decode the body or essentials
   - decodeVaa{Body,Essentials}{Cd,Mem}

Additionally, a few convenience functions are provided
- skipVaaVersionAndHeader{Cd,Mem}, which skips the version and header for any version.
    This is useful if you want to read the full envelope.
- decodeVaaSimple{Cd,Mem}, which decodes the essentials and payload for any version.
    For most common use cases, this is the only function you need for decoding.

Example decoding usage:
NOTE: This does not perform any verification, it only decodes the VAA!

```
// 1. Start with the bytes array containing the encoded VAA
bytes calldata encodedVaa = ...; // The encoded VAA is contained in this bytes array(can be calldata or memory)
uint256 offset = ...; // The offset to start decoding from, usually 0

// 2. Decode the essentials
uint16 emitterChainId; // The chain ID of the emitter(see constants/Chains.sol for the list of chain IDs)
bytes32 emitterAddress; // The address of the emitter(the format is chain-specific, but always limited to 32 bytes)
uint64 sequence; // The sequence number of the VAA
bytes calldata payload; // The payload of the VAA
(emitterChainId, emitterAddress, sequence, payload) = VaaLib2.decodeVaaEssentialsCd(encodedVaa, offset);

// 3. Decode the payload using your application-specific logic
```

======== Encoding ========

Encoding VAAs is supported using the following functions:
- encodeVaaHeaderMultisig(guardianSetIndex, signatures)
- encodeVaaHeaderSchnorr(guardianSetIndex, r, s)
- encodeVaaHeaderECDSA(guardianSetIndex, r, s, v)
- encodeVaaBody(timestamp, nonce, emitterChainId, emitterAddress, sequence, consistencyLevel, payload)
- encodeVaa(header, body)

Batch encoding is supported using the following function:
- encodeVaaBatch(encodedVaas)
- encodeVaaBatch(version, encodedVaas)
- encodeVaaBatch(version, keyIndex, encodedVaas)

The more specific functions will have a lower cost, but can only be used when the version/keyIndex
of all VAAs in the batch are the same. For production, it's recommended to use the most specific
function you can based on your use case.

The batch encoding functions are provided primarily for testing and debugging purposes, and to serve
as a reference for off-chain libraries. In production, you should instead call the wormhole core
contract to create VAAs. For batching, it's recommended to encode the batch off-chain and then submit
the entire batch as a single encoded batch to the verification functions below.

To create a test VAA, first encode the body then sign the keccak256 hash of the encoded body with
the private key of the guardian(s). Finally, encode the header.

Example encoding usage:
```
// 1. Create the payload, body, and hash it to get the bodyHash
bytes memory payload = ...;
bytes memory body = encodeVaaBodyCd(timestamp, nonce, emitterChainId, emitterAddress, sequence, consistencyLevel, payload);
bytes32 bodyHash = keccak256(body);

// 2. Create the signature. This is not provided by VaaLib2, you must implement this yourself.
bytes memory signatures = ...;

// 3. Encode the header and VAA from the body and signature(s)
//    - Make sure you use the correct header function for your desired VAA version
bytes memory header = encodeVaaHeaderMultisig(guardianSetIndex, signatures);
bytes memory encodedVaa = encodeVaa(header, body);
```

======== Verification ========

The verifier contract is responsible for verifying VAAs. It provides a `verify` function for single
VAAs of any version, and a `verifyBatch` function for batches of VAAs.

```
// Example of verifying a single VAA
WormholeVerifier verifier = ...;
bytes calldata encodedVaa = ...;

(
  uint16 emitterChainId,
  bytes32 emitterAddress,
  uint64 sequence,
  uint16 payloadOffset
) = verifier.verify(encodedVaa);

// Or for a batch
(bool success, bytes memory resultBytes) = verifier.verifyBatch(encodedVaas);
(uint256 result, ) = resultBytes.asUint256CdUnchecked(0);
return success && ((result & VaaLib2.ERROR_MASK) == 0);
```

*/

library VaaLib2 {
  using BytesParsing for bytes;

  // Batching
  // This is the selector for the batching function in the wormhole verifier V2/V3 contract
  // NOTE: It's included here to avoid an import
  bytes4 private constant VAA_BATCH_SELECTOR = 0xacc6a7d9;

  // Versions
  uint8 public constant VERSION_MULTISIG = 0x01;
  uint8 public constant VERSION_SCHNORR  = 0x02;
  uint8 public constant VERSION_ECDSA    = 0x03;

  // Errors
  uint256 public constant ERROR_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000;

  // -------- Decoding --------
  // Step 1: Decode the version, which tells us which header to decode
  function decodeVaaHeaderVersionCd(
    bytes calldata encodedVaa,
    uint256 offset
  ) internal pure returns (uint8 version, uint256 newOffset) {
    (version, newOffset) = encodedVaa.asUint8CdUnchecked(offset);
  }

  function decodeVaaHeaderVersionMem(
    bytes memory encodedVaa,
    uint256 offset
  ) internal pure returns (uint8 version, uint256 newOffset) {
    (version, newOffset) = encodedVaa.asUint8MemUnchecked(offset);
  }

  // Step 2: Decode the header based on the version
  // - Multisig
  function decodeVaaHeaderMultisigCd(
    bytes calldata encodedVaa,
    uint256 offset
  ) internal pure returns (uint32 guardianSetIndex, GuardianSignature[] memory signatures, uint256 newOffset) {
    (guardianSetIndex, newOffset) = encodedVaa.asUint32CdUnchecked(offset);
    uint8 signatureCount;
    (signatureCount, newOffset) = encodedVaa.asUint8CdUnchecked(newOffset);
    signatures = new GuardianSignature[](signatureCount);
    for (uint256 i = 0; i < signatureCount; i++) {
      (signatures[i], newOffset) = VaaLib.decodeGuardianSignatureStructCdUnchecked(encodedVaa, newOffset);
    }
  }

  function decodeVaaHeaderMultisigMem(
    bytes memory encodedVaa,
    uint256 offset
  ) internal pure returns (uint32 guardianSetIndex, GuardianSignature[] memory signatures, uint256 newOffset) {
    (guardianSetIndex, newOffset) = encodedVaa.asUint32MemUnchecked(offset);
    uint8 signatureCount;
    (signatureCount, newOffset) = encodedVaa.asUint8MemUnchecked(newOffset);
    signatures = new GuardianSignature[](signatureCount);
    for (uint256 i = 0; i < signatureCount; i++) {
      (signatures[i], newOffset) = VaaLib.decodeGuardianSignatureStructMemUnchecked(encodedVaa, newOffset);
    }
  }

  // - Schnorr
  function decodeVaaHeaderSchnorrCd(
    bytes calldata encodedVaa,
    uint256 offset
  ) internal pure returns (uint32 guardianSetIndex, address r, uint256 s, uint256 newOffset) {
    (guardianSetIndex, newOffset) = encodedVaa.asUint32CdUnchecked(offset);
    (r, newOffset) = encodedVaa.asAddressCdUnchecked(newOffset);
    (s, newOffset) = encodedVaa.asUint256CdUnchecked(newOffset);
  }

  function decodeVaaHeaderSchnorrMem(
    bytes memory encodedVaa,
    uint256 offset
  ) internal pure returns (uint32 guardianSetIndex, address r, uint256 s, uint256 newOffset) {
    (guardianSetIndex, newOffset) = encodedVaa.asUint32MemUnchecked(offset);
    (r, newOffset) = encodedVaa.asAddressMemUnchecked(newOffset);
    (s, newOffset) = encodedVaa.asUint256MemUnchecked(newOffset);
  }

  // - ECDSA
  function decodeVaaHeaderECDSACd(
    bytes calldata encodedVaa,
    uint256 offset
  ) internal pure returns (uint32 guardianSetIndex, uint256 r, uint256 s, uint8 v, uint256 newOffset) {
    (guardianSetIndex, newOffset) = encodedVaa.asUint32CdUnchecked(offset);
    (r, newOffset) = encodedVaa.asUint256CdUnchecked(newOffset);
    (s, newOffset) = encodedVaa.asUint256CdUnchecked(newOffset);
    (v, newOffset) = encodedVaa.asUint8CdUnchecked(newOffset);
  }

  function decodeVaaHeaderECDSAMem(
    bytes memory encodedVaa,
    uint256 offset
  ) internal pure returns (uint32 guardianSetIndex, uint256 r, uint256 s, uint8 v, uint256 newOffset) {
    (guardianSetIndex, newOffset) = encodedVaa.asUint32MemUnchecked(offset);
    (r, newOffset) = encodedVaa.asUint256MemUnchecked(newOffset);
    (s, newOffset) = encodedVaa.asUint256MemUnchecked(newOffset);
    (v, newOffset) = encodedVaa.asUint8MemUnchecked(newOffset);
  }

  // Step 3: Decode the envelope
  // - Envelope
  function decodeVaaBodyCd(
    bytes calldata encodedVaa,
    uint256 offset
  ) internal pure returns (
    uint32 timestamp,
    uint32 nonce,
    uint16 emitterChainId,
    bytes32 emitterAddress,
    uint64 sequence,
    uint8 consistencyLevel,
    bytes calldata payload
  ) {
    return VaaLib.decodeVaaBodyCd(encodedVaa, offset);
  }

  function decodeVaaBodyMem(
    bytes memory encodedVaa,
    uint256 offset
  ) internal pure returns (
    uint32 timestamp,
    uint32 nonce,
    uint16 emitterChainId,
    bytes32 emitterAddress,
    uint64 sequence,
    uint8 consistencyLevel,
    bytes memory payload
  ) {
    unchecked {
      (bytes memory encodedVaaSlice, ) = encodedVaa.sliceMemUnchecked(offset, encodedVaa.length - offset);
      return VaaLib.decodeVaaBodyMem(encodedVaaSlice);
    }
  }

  // - Essentials
  function decodeVaaEssentialsCd(
    bytes calldata encodedVaa,
    uint256 offset
  ) internal pure returns (
    uint16 emitterChainId,
    bytes32 emitterAddress,
    uint64 sequence,
    bytes calldata payload
  ) {
    unchecked {
      // NOTE: We can't use the VaaLib.decodeVaaEssentialsCd function here because it checks the version
      offset += 8; // Skip the timestamp and nonce
      (emitterChainId, offset) = encodedVaa.asUint16CdUnchecked(offset);
      (emitterAddress, offset) = encodedVaa.asBytes32CdUnchecked(offset);
      (sequence,       offset) = encodedVaa.asUint64CdUnchecked(offset);
      offset += 1; // Skip the consistency level
      (payload,) = encodedVaa.sliceCdUnchecked(offset, encodedVaa.length - offset);
    }
  }

  function decodeVaaEssentialsMem(
    bytes memory encodedVaa,
    uint256 offset
  ) internal pure returns (
    uint16 emitterChainId,
    bytes32 emitterAddress,
    uint64 sequence,
    bytes memory payload
  ) {
    unchecked {
      // NOTE: We can't use the VaaLib.decodeVaaEssentialsMem function here because it checks the version
      offset += 8; // Skip the timestamp and nonce
      (emitterChainId, offset) = encodedVaa.asUint16MemUnchecked(offset);
      (emitterAddress, offset) = encodedVaa.asBytes32MemUnchecked(offset);
      (sequence, offset) = encodedVaa.asUint64MemUnchecked(offset);
      offset += 1; // Skip the consistency level
      (payload,) = encodedVaa.sliceMemUnchecked(offset, encodedVaa.length - offset);
    }
  }

  // Convenience functions
  function skipVaaVersionAndHeaderCd(
    bytes calldata encodedVaa,
    uint256 offset
  ) internal pure returns (uint256 newOffset) {
    uint8 version;
    (version, newOffset) = decodeVaaHeaderVersionCd(encodedVaa, offset);
    if (version == VERSION_ECDSA) {
      (,,,, newOffset) = decodeVaaHeaderECDSACd(encodedVaa, newOffset);
    } else if (version == VERSION_SCHNORR) {
      (,,, newOffset) = decodeVaaHeaderSchnorrCd(encodedVaa, newOffset);
    } else if (version == VERSION_MULTISIG) {
      (,, newOffset) = decodeVaaHeaderMultisigCd(encodedVaa, newOffset);
    } else {
      revert VaaLib.InvalidVersion(version);
    }
  }

  function skipVaaVersionAndHeaderMem(
    bytes memory encodedVaa,
    uint256 offset
  ) internal pure returns (uint256 newOffset) {
    uint8 version;
    (version, newOffset) = decodeVaaHeaderVersionMem(encodedVaa, offset);
  }

  function decodeVaaSimpleCd(
    bytes calldata encodedVaa,
    uint256 offset
  ) internal pure returns (
    uint16 emitterChainId,
    bytes32 emitterAddress,
    uint64 sequence,
    bytes calldata payload
  ) {
    offset = skipVaaVersionAndHeaderCd(encodedVaa, offset);
    (emitterChainId, emitterAddress, sequence, payload) = decodeVaaEssentialsCd(encodedVaa, offset);
  }

  function decodeVaaSimpleMem(
    bytes memory encodedVaa,
    uint256 offset
  ) internal pure returns (
    uint16 emitterChainId,
    bytes32 emitterAddress,
    uint64 sequence,
    bytes memory payload
  ) {
    offset = skipVaaVersionAndHeaderMem(encodedVaa, offset);
    (emitterChainId, emitterAddress, sequence, payload) = decodeVaaEssentialsMem(encodedVaa, offset);
  }

  // -------- Encoding single VAAs --------

  function encodeVaa(
    bytes memory header,
    bytes memory body
  ) internal pure returns (bytes memory encodedVaa) {
    return abi.encodePacked(header, body);
  }

  function encodeVaaHeaderMultisig(
    uint32 guardianSetIndex,
    GuardianSignature[] memory signatures
  ) internal pure returns (bytes memory result) {
    return VaaLib.encodeVaaHeader(guardianSetIndex, signatures);
  }

  function encodeVaaHeaderSchnorr(
    uint32 guardianSetIndex,
    address r,
    uint256 s
  ) internal pure returns (bytes memory result) {
    return abi.encodePacked(VERSION_SCHNORR, guardianSetIndex, r, s);
  }

  function encodeVaaHeaderECDSA(
    uint32 guardianSetIndex,
    uint256 r,
    uint256 s,
    uint8 v
  ) internal pure returns (bytes memory result) {
    return abi.encodePacked(VERSION_ECDSA, guardianSetIndex, r, s, v);
  }

  function encodeVaaBody(
    uint32 timestamp,
    uint32 nonce,
    uint16 emitterChainId,
    bytes32 emitterAddress,
    uint64 sequence,
    uint8 consistencyLevel,
    bytes memory payload
  ) internal pure returns (bytes memory result) {
    return abi.encodePacked(timestamp, nonce, emitterChainId, emitterAddress, sequence, consistencyLevel, payload);
  }

  // -------- Batching --------

  function encodeVaaBatch(
    bytes[] memory encodedVaas
  ) internal pure returns (bytes memory result) {
    result = new bytes(0);
    for (uint256 i = 0; i < encodedVaas.length; i++) {
      result = abi.encodePacked(result, encodedVaas[i]);
    }
    return abi.encodePacked(VAA_BATCH_SELECTOR, result);
  }

  function encodeVaaBatch(
    uint8 version,
    bytes[] memory encodedVaas
  ) internal pure returns (bytes memory result) {
    result = new bytes(0);
    for (uint256 i = 0; i < encodedVaas.length; i++) {
      uint256 offset = 0;
      uint8 actualVesion;
      bytes memory encodedVaaSlice;

      (actualVesion, offset) = encodedVaas[i].asUint8MemUnchecked(offset);
      (encodedVaaSlice, offset) = encodedVaas[i].sliceMemUnchecked(offset, encodedVaas[i].length - offset);
      
      require(actualVesion == version, "Invalid version");

      result = abi.encodePacked(result, encodedVaaSlice);
    }

    return result;
  }

  function encodeVaaBatch(
    uint8 version,
    uint8 keyIndex,
    bytes[] memory encodedVaas
  ) internal pure returns (bytes memory result) {
    result = new bytes(0);
    for (uint256 i = 0; i < encodedVaas.length; i++) {
      uint256 offset = 0;
      uint8 actualVesion;
      uint32 actualKeyIndex;
      bytes memory encodedVaaSlice;

      (actualVesion, offset) = encodedVaas[i].asUint8MemUnchecked(offset);
      (actualKeyIndex, offset) = encodedVaas[i].asUint32MemUnchecked(offset);
      (encodedVaaSlice, offset) = encodedVaas[i].sliceMemUnchecked(offset, encodedVaas[i].length - offset);

      require(actualVesion == version, "Invalid version");
      require(actualKeyIndex == keyIndex, "Invalid key index");

      result = abi.encodePacked(result, encodedVaaSlice);
    }

    return result;
  }
}
