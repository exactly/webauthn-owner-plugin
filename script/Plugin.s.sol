// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { Script } from "forge-std/Script.sol";

import { WebauthnOwnerPlugin } from "../src/WebauthnOwnerPlugin.sol";

contract PluginScript is Script {
  WebauthnOwnerPlugin public plugin;

  function run() external {
    assert(msg.sender != DEFAULT_SENDER);

    vm.broadcast(msg.sender);
    plugin = new WebauthnOwnerPlugin();
  }
}
