// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { IMultiOwnerPlugin } from "modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";

interface IWebauthnOwnerPlugin is IMultiOwnerPlugin {
  /// @notice This event is emitted when owners of the account are updated.
  /// @param account The account whose ownership changed.
  /// @param addedOwners The public key or address array of added owners.
  /// @param removedOwners The public key or address array of removed owners.
  event OwnerUpdated(address indexed account, PublicKey[] addedOwners, PublicKey[] removedOwners);

  error InvalidEthereumAddressOwner(bytes32 owner);

  function ownersPublicKeysOf(address account) external view returns (PublicKey[] memory owners);
  function ownerIndexOf(address account, PublicKey calldata owner) external view returns (uint8 index);

  function updateOwnersPublicKeys(PublicKey[] memory ownersToAdd, PublicKey[] memory ownersToRemove) external;
}

/// @dev Only 64 sequential public keys can be associated (https://eips.ethereum.org/EIPS/eip-7562#validation-rules).
uint256 constant MAX_OWNERS = 64;

struct PublicKey {
  uint256 x;
  uint256 y;
}
