// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { Script, VmSafe, stdJson } from "forge-std/Script.sol";

import { LibString } from "solady/utils/LibString.sol";

import { WebauthnModularAccountFactory } from "../src/WebauthnModularAccountFactory.sol";

contract StakeScript is Script {
  using LibString for uint256;
  using stdJson for string;

  WebauthnModularAccountFactory public factory;

  function setUp() external {
    VmSafe.DirEntry[] memory broadcasts = vm.readDir(string.concat("broadcast/Deploy.s.sol/", block.chainid.toString()));
    factory = WebauthnModularAccountFactory(
      payable(vm.readFile(broadcasts[broadcasts.length - 1].path).readAddress(".transactions[1].contractAddress"))
    );
  }

  function run() external {
    assert(msg.sender != DEFAULT_SENDER);

    vm.broadcast(msg.sender);
    factory.addStake{ value: 0.1 ether }(1 days, 0.1 ether);
  }
}
