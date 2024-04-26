// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { Script } from "forge-std/Script.sol";

import { UpgradeableModularAccount } from "modular-account/src/account/UpgradeableModularAccount.sol";
import { IEntryPoint } from "modular-account/src/interfaces/erc4337/IEntryPoint.sol";

import { WebauthnModularAccountFactory } from "../src/WebauthnModularAccountFactory.sol";
import { WebauthnOwnerPlugin } from "../src/WebauthnOwnerPlugin.sol";

contract DeployScript is Script {
  IEntryPoint public constant ENTRYPOINT = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789); // v0.6.0

  WebauthnOwnerPlugin public plugin;
  WebauthnModularAccountFactory public factory;

  function run() external {
    vm.startBroadcast();

    plugin = new WebauthnOwnerPlugin();
    factory = new WebauthnModularAccountFactory(
      address(msg.sender),
      address(plugin),
      address(new UpgradeableModularAccount(ENTRYPOINT)),
      keccak256(abi.encode(plugin.pluginManifest())),
      ENTRYPOINT
    );

    vm.stopBroadcast();
  }
}
