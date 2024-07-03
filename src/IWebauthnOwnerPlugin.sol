// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { IMultiOwnerPlugin } from "modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";

interface IWebauthnOwnerPlugin is IMultiOwnerPlugin {
  /// @notice This event is emitted when owners of the account are updated.
  /// @param account The account whose ownership changed.
  /// @param addedOwners The public key or address array of added owners.
  /// @param removedOwners The public key or address array of removed owners.
  event OwnerUpdated(address indexed account, PublicKey[] addedOwners, PublicKey[] removedOwners);

  /// @notice Thrown if a provided owner is 32 bytes long but does not fit in an `address` type.
  /// @param owner The invalid owner.
  error InvalidEthereumAddressOwner(bytes32 owner);

  /// @notice Get the public keys of the owners of `account`.
  /// @param account The account to get the owners of.
  /// @return owners The public keys of the owners of the account.
  function ownersPublicKeysOf(address account) external view returns (PublicKey[] memory owners);

  /// @notice Get the index of an owner in the owners array of `account`.
  /// @param account The account to get the owners of.
  /// @param owner The owner to get the index of.
  /// @return index The index of the owner in the owners array.
  function ownerIndexOf(address account, PublicKey calldata owner) external view returns (uint8 index);

  /// @notice Update owners of the account. Owners can update owners.
  /// @dev This function is installed on the account as part of plugin installation, and should
  ///      only be called from an account.
  /// @param ownersToAdd The public key array of owners to be added.
  /// @param ownersToRemove The public key array of owners to be removed.
  function updateOwnersPublicKeys(PublicKey[] memory ownersToAdd, PublicKey[] memory ownersToRemove) external;
}

/// @dev Only 64 sequential public keys can be associated (https://eips.ethereum.org/EIPS/eip-7562#validation-rules).
uint256 constant MAX_OWNERS = 64;

struct PublicKey {
  uint256 x;
  uint256 y;
}
