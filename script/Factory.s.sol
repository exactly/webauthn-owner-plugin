// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { Script, stdJson } from "forge-std/Script.sol";

import { IEntryPoint } from "modular-account/src/interfaces/erc4337/IEntryPoint.sol";

import { LibString } from "solady/utils/LibString.sol";

import { WebauthnModularAccountFactory } from "../src/WebauthnModularAccountFactory.sol";
import { WebauthnOwnerPlugin } from "../src/WebauthnOwnerPlugin.sol";

address constant ACCOUNT_IMPL = 0x0046000000000151008789797b54fdb500E2a61e; // v1.0.0
IEntryPoint constant ENTRYPOINT = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789); // v0.6.0

contract FactoryScript is Script {
  using LibString for uint256;
  using stdJson for string;

  WebauthnOwnerPlugin public plugin;
  WebauthnModularAccountFactory public factory;

  function setUp() external {
    plugin = WebauthnOwnerPlugin(
      vm.readFile(string.concat("broadcast/Plugin.s.sol/", block.chainid.toString(), "/run-latest.json")).readAddress(
        ".transactions[0].contractAddress"
      )
    );
  }

  function run() external {
    assert(msg.sender != DEFAULT_SENDER);

    vm.startBroadcast(msg.sender);
    factory = new WebauthnModularAccountFactory(
      msg.sender, address(plugin), ACCOUNT_IMPL, keccak256(abi.encode(plugin.pluginManifest())), ENTRYPOINT
    );
    factory.addStake{ value: 0.1 ether }(1 days, 0.1 ether);
    vm.stopBroadcast();
  }
}
