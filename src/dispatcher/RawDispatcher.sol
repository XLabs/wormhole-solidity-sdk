// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.4;

/**
 * @title RawDispatcher
 * @notice Allows implementing custom call dispatching logic that is more efficient than 
 * Solidity's default dispatching which simply sorts all public functions in ascending 
 * order by their selector.
 * @notice The numbers in the function names of this contract are meaningless and only 
 * serve the purpose of yielding a low selector that will guarantee that these functions
 * will come first in Solidity's default sorting.
 * @dev It's recommended to implement a hierarchical dispatching logic that allows 
 * batching multiple function calls. Return values of sub-calls should be concatenated.
 */
abstract contract RawDispatcher {

  /**
   * @custom:selector 00000eb6
   */
  function exec768() external payable returns (bytes memory) {
    return _exec(msg.data[4:]);
  }

  /**
   * @custom:selector 0008a112
   */
  function get1959() external view returns (bytes memory) {
    return _get(msg.data[4:]);
  }

  function _exec(bytes calldata data) internal virtual returns (bytes memory);

  function _get(bytes calldata data) internal view virtual returns (bytes memory);
}