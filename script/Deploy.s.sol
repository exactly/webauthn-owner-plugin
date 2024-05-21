// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { Script } from "forge-std/Script.sol";

import { IEntryPoint } from "modular-account/src/interfaces/erc4337/IEntryPoint.sol";

import { WebauthnModularAccountFactory } from "../src/WebauthnModularAccountFactory.sol";
import { WebauthnOwnerPlugin } from "../src/WebauthnOwnerPlugin.sol";

contract DeployScript is Script {
  address public constant ACCOUNT_IMPL = 0x0046000000000151008789797b54fdb500E2a61e; // v1.0.0
  IEntryPoint public constant ENTRYPOINT = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789); // v0.6.0

  WebauthnOwnerPlugin public plugin;
  WebauthnModularAccountFactory public factory;

  function run() external {
    assert(msg.sender != DEFAULT_SENDER);

    vm.startBroadcast(msg.sender);

    plugin = new WebauthnOwnerPlugin();
    factory = new WebauthnModularAccountFactory(
      msg.sender, address(plugin), ACCOUNT_IMPL, keccak256(abi.encode(plugin.pluginManifest())), ENTRYPOINT
    );
    factory.addStake{ value: 0.1 ether }(1 days, 0.1 ether);

    vm.stopBroadcast();
  }
}
