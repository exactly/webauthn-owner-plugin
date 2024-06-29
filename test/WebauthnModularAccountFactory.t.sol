// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { Test } from "forge-std/Test.sol";

import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";

import { PluginManagerInternals } from "modular-account/src/account/PluginManagerInternals.sol";
import { UpgradeableModularAccount } from "modular-account/src/account/UpgradeableModularAccount.sol";

import { ECDSA } from "solady/utils/ECDSA.sol";

import { DeployScript } from "../script/Deploy.s.sol";
import { OwnersLib } from "../src/OwnersLib.sol";
import { OwnersLimitExceeded, WebauthnModularAccountFactory } from "../src/WebauthnModularAccountFactory.sol";
import { IMultiOwnerPlugin, MAX_OWNERS, PublicKey, WebauthnOwnerPlugin } from "../src/WebauthnOwnerPlugin.sol";

// solhint-disable func-name-mixedcase
contract WebauthnModularAccountFactoryTest is Test {
  using OwnersLib for address[];
  using ECDSA for bytes32;

  EntryPoint public entryPoint;
  WebauthnModularAccountFactory public factory;
  WebauthnOwnerPlugin public plugin;

  address public notOwner = address(1);
  address public owner1 = address(2);
  address public owner2 = address(3);
  address public badImpl = address(4);

  address[] public owners;
  address[] public largeOwners;

  PublicKey public passkeyOwner = abi.decode(
    hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d",
    (PublicKey)
  );
  uint256 public passkeyOwnerKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);

  bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

  function setUp() external {
    DeployScript deploy = new DeployScript();
    entryPoint = EntryPoint(payable(address(deploy.ENTRYPOINT())));
    vm.etch(address(entryPoint), address(new EntryPoint()).code);
    vm.etch(deploy.ACCOUNT_IMPL(), address(new UpgradeableModularAccount(deploy.ENTRYPOINT())).code);
    deploy.run();
    plugin = deploy.plugin();
    factory = deploy.factory();
    factory.unlockStake();
    skip(entryPoint.getDepositInfo(address(factory)).unstakeDelaySec);
    factory.withdrawStake(payable(0));

    owners.push(owner1);
    owners.push(owner2);
    for (uint160 i = 0; i < MAX_OWNERS; i++) {
      largeOwners.push(address(i + 1));
    }
  }

  function test_addressMatch() external {
    address predicted = factory.getAddress(0, owners.toPublicKeys());
    address deployed = factory.createAccount(0, owners.toPublicKeys());
    assertEq(predicted, deployed);
  }

  function test_deploy() external {
    address deployed = factory.createAccount(0, owners.toPublicKeys());

    // test that the deployed account is initialized
    assertEq(address(UpgradeableModularAccount(payable(deployed)).entryPoint()), address(entryPoint));

    // test that the deployed account installed owner plugin correctly
    address[] memory actualOwners = plugin.ownersOf(deployed);
    assertEq(actualOwners.length, 2);
    assertEq(actualOwners[0], owner1);
    assertEq(actualOwners[1], owner2);
  }

  function test_deploy_PasskeyOwner() external {
    PublicKey[] memory ownerKeys = new PublicKey[](1);
    ownerKeys[0] = passkeyOwner;
    address deployed = factory.createAccount(0, ownerKeys);

    // test that the deployed account is initialized
    assertEq(address(UpgradeableModularAccount(payable(deployed)).entryPoint()), address(entryPoint));

    // test that the deployed account installed owner plugin correctly
    PublicKey[] memory actualOwners = plugin.ownersPublicKeysOf(deployed);
    assertEq(actualOwners.length, 1);
    assertEq(abi.encode(actualOwners[0]), abi.encode(passkeyOwner));
  }

  function test_deployCollision() external {
    address deployed = factory.createAccount(0, owners.toPublicKeys());

    uint256 gasStart = gasleft();

    // deploy 2nd time which should short circuit
    // test for short circuit -> call should cost less than a CREATE2, or 32000 gas
    address secondDeploy = factory.createAccount(0, owners.toPublicKeys());

    assertApproxEqAbs(gasleft(), gasStart, 31_999);
    assertEq(deployed, secondDeploy);
  }

  function test_deployedAccountHasCorrectPlugins() external {
    address deployed = factory.createAccount(0, owners.toPublicKeys());

    // check installed plugins on account
    address[] memory plugins = UpgradeableModularAccount(payable(deployed)).getInstalledPlugins();
    assertEq(plugins.length, 1);
    assertEq(plugins[0], address(plugin));
  }

  function test_badOwnersArray() external {
    vm.expectRevert(IMultiOwnerPlugin.EmptyOwnersNotAllowed.selector);
    factory.getAddress(0, new PublicKey[](0));

    address[] memory badOwners = new address[](2);

    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, address(0)));
    factory.getAddress(0, badOwners.toPublicKeys());

    badOwners[0] = address(1);
    badOwners[1] = address(1);

    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, address(1)));
    factory.getAddress(0, badOwners.toPublicKeys());
  }

  function test_addStake() public {
    assertEq(entryPoint.balanceOf(address(factory)), 0);
    vm.deal(address(this), 100 ether);
    factory.addStake{ value: 10 ether }(10 hours, 10 ether);
    assertEq(entryPoint.getDepositInfo(address(factory)).stake, 10 ether);
  }

  function test_unlockStake() public {
    test_addStake();
    factory.unlockStake();
    assertEq(entryPoint.getDepositInfo(address(factory)).withdrawTime, block.timestamp + 10 hours);
  }

  function test_withdrawStake() external {
    test_unlockStake();
    skip(10 hours - 1);
    vm.expectRevert("Stake withdrawal is not due");
    factory.withdrawStake(payable(address(this)));
    assertEq(address(this).balance, 90 ether);
    skip(1);
    factory.withdrawStake(payable(address(this)));
    assertEq(address(this).balance, 100 ether);
  }

  function test_withdraw() external {
    factory.addStake{ value: 10 ether }(10 hours, 1 ether);
    assertEq(address(factory).balance, 9 ether);
    factory.withdraw(payable(address(this)), address(0), 0); // amount = balance if native currency
    assertEq(address(factory).balance, 0);
  }

  function test_2StepOwnershipTransfer() external {
    assertEq(factory.owner(), address(this));
    factory.transferOwnership(owner1);
    assertEq(factory.owner(), address(this));
    vm.prank(owner1);
    factory.acceptOwnership();
    assertEq(factory.owner(), owner1);
  }

  function test_getAddressWithMaxOwnersAndDeploy() external {
    address addr = factory.getAddress(0, largeOwners.toPublicKeys());
    assertEq(addr, factory.createAccount(0, largeOwners.toPublicKeys()));
  }

  function test_getAddressWithTooManyOwners() external {
    largeOwners.push(address(101));
    vm.expectRevert(OwnersLimitExceeded.selector);
    factory.getAddress(0, largeOwners.toPublicKeys());
  }

  function test_getAddressWithUnsortedOwners() external {
    address[] memory tempOwners = new address[](2);
    tempOwners[0] = address(2);
    tempOwners[1] = address(1);
    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, address(1)));
    factory.getAddress(0, tempOwners.toPublicKeys());
  }

  function test_deployWithDuplicateOwners() external {
    address[] memory tempOwners = new address[](2);
    tempOwners[0] = address(1);
    tempOwners[1] = address(1);

    vm.expectRevert(
      abi.encodeWithSelector(
        PluginManagerInternals.PluginInstallCallbackFailed.selector,
        plugin,
        abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, address(1))
      )
    );
    factory.createAccount(0, tempOwners.toPublicKeys());
  }

  function test_deployWithUnsortedOwners() external {
    address[] memory tempOwners = new address[](2);
    tempOwners[0] = address(2);
    tempOwners[1] = address(1);
    vm.expectRevert(
      abi.encodeWithSelector(
        PluginManagerInternals.PluginInstallCallbackFailed.selector,
        plugin,
        abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, address(1))
      )
    );
    factory.createAccount(0, tempOwners.toPublicKeys());
  }

  // to receive funds from withdraw
  receive() external payable { }
}
