// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { MAX_OWNERS, PublicKey } from "./IWebauthnOwnerPlugin.sol";

library OwnersLib {
  function get(Owners storage owners, uint256 index) internal view returns (PublicKey memory) {
    if (index >= owners.length) revert IndexOutOfBounds();
    return owners.publicKeys[index];
  }

  function all(Owners storage owners) internal view returns (PublicKey[] memory publicKeys) {
    uint256 length = owners.length;
    publicKeys = new PublicKey[](length);
    for (uint256 i = 0; i < length; ++i) {
      publicKeys[i] = owners.publicKeys[i];
    }
  }

  function allAddresses(Owners storage owners) internal view returns (address[] memory addresses) {
    uint256 length = owners.length;
    addresses = new address[](length);
    for (uint256 i = 0; i < length; ++i) {
      addresses[i] = owners.publicKeys[i].y == 0
        ? address(uint160(uint256(owners.publicKeys[i].x)))
        : address(bytes20(keccak256(abi.encode(owners.publicKeys[i]))));
    }
  }

  function all64(Owners storage owners) internal view returns (uint256 length, PublicKey[MAX_OWNERS] memory publicKeys) {
    length = owners.length;
    for (uint256 i = 0; i < length; ++i) {
      publicKeys[i] = owners.publicKeys[i];
    }
  }

  function contains(Owners storage owners, address ownerAddress) internal view returns (bool) {
    PublicKey memory owner = PublicKey(uint256(uint160(ownerAddress)), 0);
    uint256 length = owners.length;
    for (uint256 i = 0; i < length; ++i) {
      if (owners.publicKeys[i].x == owner.x && owners.publicKeys[i].y == owner.y) return true;
    }
    return false;
  }

  function contains(PublicKey[MAX_OWNERS] memory keys, PublicKey memory owner, uint256 length)
    internal
    pure
    returns (bool)
  {
    for (uint256 i = 0; i < length; ++i) {
      if (keys[i].x == owner.x && keys[i].y == owner.y) return true;
    }
    return false;
  }

  function find(PublicKey[MAX_OWNERS] memory keys, PublicKey memory owner, uint256 length)
    internal
    pure
    returns (uint256)
  {
    for (uint256 i = 0; i < length; ++i) {
      if (keys[i].x == owner.x && keys[i].y == owner.y) return i;
    }
    return type(uint256).max;
  }

  function toPublicKeys(address[] memory addresses) internal pure returns (PublicKey[] memory publicKeys) {
    publicKeys = new PublicKey[](addresses.length);
    for (uint256 i = 0; i < addresses.length; ++i) {
      publicKeys[i] = PublicKey(uint256(uint160(addresses[i])), 0);
    }
  }

  function toAddress(PublicKey memory owner) internal pure returns (address) {
    return owner.y == 0 ? address(uint160(uint256(owner.x))) : address(bytes20(keccak256(abi.encode(owner))));
  }

  function toAddresses(PublicKey[] memory owners) internal pure returns (address[] memory addresses) {
    addresses = new address[](owners.length);
    for (uint256 i = 0; i < owners.length; ++i) {
      addresses[i] = toAddress(owners[i]);
    }
  }

  /// @dev Negated semantics for gas savings.
  function isInvalid(PublicKey memory owner) internal pure returns (bool) {
    return owner.y == 0 && (owner.x == 0 || owner.x > type(uint160).max);
  }

  function equals(PublicKey memory a, PublicKey memory b) internal pure returns (bool) {
    return a.x == b.x && a.y == b.y;
  }
}

struct Owners {
  uint256 length;
  PublicKey[MAX_OWNERS] publicKeys;
}

error IndexOutOfBounds();
