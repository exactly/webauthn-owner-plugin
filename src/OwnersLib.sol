// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.25;

library OwnersLib {
  function push(Owners storage owners, bytes32[2][] memory values) internal {
    uint256 length = owners.length;
    for (uint256 i = 0; i < values.length; ++i) {
      owners.data[length + i] = values[i];
    }
    owners.length = length + values.length;
  }

  function reset(Owners storage owners) internal {
    owners.length = 0;
  }

  function get(Owners storage owners, uint256 index) internal view returns (bytes32[2] memory) {
    if (index >= owners.length) revert IndexOutOfBounds();
    return owners.data[index];
  }

  function all(Owners storage owners) internal view returns (bytes32[2][] memory array) {
    array = new bytes32[2][](owners.length);
    for (uint256 i = 0; i < array.length; ++i) {
      array[i] = owners.data[i];
    }
  }

  function allAddresses(Owners storage owners) internal view returns (address[] memory addresses) {
    addresses = new address[](owners.length);
    for (uint256 i = 0; i < addresses.length; ++i) {
      addresses[i] = owners.data[i][1] == bytes32(0)
        ? address(uint160(uint256(owners.data[i][0])))
        : address(bytes20(keccak256(abi.encode(owners.data[i]))));
    }
  }

  function allFixed(Owners storage owners) internal view returns (bytes32[2][64] memory array) {
    for (uint256 i = 0; i < array.length; ++i) {
      array[i] = owners.data[i];
      if (array[i][0] == bytes32(0)) break;
    }
  }

  function contains(Owners storage owners, address ownerAddress) internal view returns (bool) {
    bytes32[2] memory owner = [bytes32(uint256(uint160(ownerAddress))), 0];
    uint256 length = owners.length;
    for (uint256 i = 0; i < length; ++i) {
      if (owners.data[i][0] == owner[0] && owners.data[i][1] == owner[1]) return true;
    }
    return false;
  }

  function contains(bytes32[2][64] memory array, bytes32[2] memory owner) internal pure returns (bool) {
    for (uint256 i = 0; i < array.length; ++i) {
      if (array[i][0] == owner[0] && array[i][1] == owner[1]) return true;
      if (array[i][0] == bytes32(0)) break;
    }
    return false;
  }

  function toBytes(address ownerAddress) internal pure returns (bytes32[2] memory) {
    return [bytes32(uint256(uint160(ownerAddress))), 0];
  }

  function toBytes(address[] memory addresses) internal pure returns (bytes32[2][] memory addressesBytes) {
    addressesBytes = new bytes32[2][](addresses.length);
    for (uint256 i = 0; i < addresses.length; ++i) {
      addressesBytes[i] = [bytes32(uint256(uint160(addresses[i]))), 0];
    }
  }

  function toAddress(bytes32[2] memory owner) internal pure returns (address) {
    return owner[1] == bytes32(0) ? address(uint160(uint256(owner[0]))) : address(bytes20(keccak256(abi.encode(owner))));
  }

  function equals(bytes32[2] memory a, bytes32[2] memory b) internal pure returns (bool) {
    return a[0] == b[0] && a[1] == b[1];
  }
}

struct Owners {
  uint256 length;
  bytes32[2][64] data;
}

error IndexOutOfBounds();
