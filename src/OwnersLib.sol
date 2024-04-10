// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.25;

import { PublicKey } from "./IWebauthnOwnerPlugin.sol";

library OwnersLib {
  function push(Owners storage owners, PublicKey[] memory values) internal {
    uint256 length = owners.length;
    for (uint256 i = 0; i < values.length; ++i) {
      owners.data[length + i] = values[i];
    }
    owners.length = length + values.length;
  }

  function reset(Owners storage owners) internal {
    owners.length = 0;
  }

  function get(Owners storage owners, uint256 index) internal view returns (PublicKey memory) {
    if (index >= owners.length) revert IndexOutOfBounds();
    return owners.data[index];
  }

  function all(Owners storage owners) internal view returns (PublicKey[] memory array) {
    array = new PublicKey[](owners.length);
    for (uint256 i = 0; i < array.length; ++i) {
      array[i] = owners.data[i];
    }
  }

  function allAddresses(Owners storage owners) internal view returns (address[] memory addresses) {
    addresses = new address[](owners.length);
    for (uint256 i = 0; i < addresses.length; ++i) {
      addresses[i] = owners.data[i].y == 0
        ? address(uint160(uint256(owners.data[i].x)))
        : address(bytes20(keccak256(abi.encode(owners.data[i]))));
    }
  }

  function allFixed(Owners storage owners) internal view returns (PublicKey[64] memory array) {
    uint256 length = owners.length;
    for (uint256 i = 0; i < length; ++i) {
      array[i] = owners.data[i];
    }
  }

  function contains(Owners storage owners, address ownerAddress) internal view returns (bool) {
    PublicKey memory owner = PublicKey(uint256(uint160(ownerAddress)), 0);
    uint256 length = owners.length;
    for (uint256 i = 0; i < length; ++i) {
      if (owners.data[i].x == owner.x && owners.data[i].y == owner.y) return true;
    }
    return false;
  }

  function contains(PublicKey[64] memory array, PublicKey memory owner, uint256 length) internal pure returns (bool) {
    for (uint256 i = 0; i < length; ++i) {
      if (array[i].x == owner.x && array[i].y == owner.y) return true;
    }
    return false;
  }

  function find(PublicKey[64] memory array, PublicKey memory owner, uint256 length) internal pure returns (uint256) {
    for (uint256 i = 0; i < length; ++i) {
      if (array[i].x == owner.x && array[i].y == owner.y) return i;
    }
    return type(uint256).max;
  }

  function toPublicKey(address[] memory addresses) internal pure returns (PublicKey[] memory publicKeys) {
    publicKeys = new PublicKey[](addresses.length);
    for (uint256 i = 0; i < addresses.length; ++i) {
      publicKeys[i] = PublicKey(uint256(uint160(addresses[i])), 0);
    }
  }

  function toAddress(PublicKey memory owner) internal pure returns (address) {
    return owner.y == 0 ? address(uint160(uint256(owner.x))) : address(bytes20(keccak256(abi.encode(owner))));
  }

  function equals(PublicKey memory a, PublicKey memory b) internal pure returns (bool) {
    return a.x == b.x && a.y == b.y;
  }
}

struct Owners {
  uint256 length;
  PublicKey[64] data;
}

error IndexOutOfBounds();
