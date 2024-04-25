// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { EntryPoint } from "account-abstraction/core/EntryPoint.sol"; // solhint-disable-line no-unused-import

import { PublicKey } from "../../src/IWebauthnOwnerPlugin.sol";

library TestLib {
  function toPublicKey(address ownerAddress) internal pure returns (PublicKey memory) {
    return PublicKey(uint256(uint160(ownerAddress)), 0);
  }
}
