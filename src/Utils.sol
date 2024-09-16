// SPDX-License-Identifier: Apache 2
pragma solidity ^0.8.19;

error NotAnEvmAddress(bytes32);

function toUniversalAddress(address addr) pure returns (bytes32 universalAddr) {
    universalAddr = bytes32(uint256(uint160(addr)));
}

function fromUniversalAddress(bytes32 universalAddr) pure returns (address addr) {
    if (bytes12(universalAddr) != 0)
        revert NotAnEvmAddress(universalAddr);

    assembly ("memory-safe") {
        addr := universalAddr
    }
}

/**
 * @dev The Solidity compiler reserves 64 bytes at the start of the memory space as "scratch space".
 * Applications can use this scratch space for short term allocations.
 * See https://docs.soliditylang.org/en/v0.8.25/assembly.html#memory-management
 */
uint256 constant scratchSpacePtr = 0x00;
/**
 * @dev We call word the typical unit size for operands of EVM instructions: 32 bytes.
 */
uint256 constant wordSize = 32;

/**
 * Hashes a 32 byte word with keccak256.
 * @param word Word to be hashed.
 */
function keccak256Word(
  bytes32 word
) pure returns (bytes32 hash) {
  /// @solidity memory-safe-assembly
  assembly {
    mstore(scratchSpacePtr, word)
    hash := keccak256(scratchSpacePtr, wordSize)
  }
}

/**
 * Reverts with a given buffer data.
 * Meant to be used to easily bubble up errors from low level calls when they fail.
 */
function forwardError(bytes memory err) pure {
    assembly ("memory-safe") {
      revert(add(err, 32), mload(err))
    }
}
