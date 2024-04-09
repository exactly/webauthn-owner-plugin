// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.25;

import { IMultiOwnerPlugin } from "modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";

interface IWebauthnOwnerPlugin is IMultiOwnerPlugin {
  /// @notice This event is emitted when owners of the account are updated.
  /// @param account The account whose ownership changed.
  /// @param addedOwners The address array of added owners.
  /// @param removedOwners The address array of removed owners.
  event OwnerUpdated(address indexed account, bytes32[2][] addedOwners, bytes32[2][] removedOwners);

  error InvalidEthereumAddressOwner(bytes32 owner);

  function ownersBytesOf(address account) external view returns (bytes32[2][] memory owners);
  function ownerIndexOf(address account, bytes32[2] calldata owner) external view returns (uint256 index);
}

struct PublicKey {
  uint256 x;
  uint256 y;
}

struct SignatureWrapper {
  uint256 ownerIndex;
  bytes signatureData;
}
