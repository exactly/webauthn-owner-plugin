// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.25;

import { Test } from "forge-std/Test.sol";

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";

import { IEntryPoint } from "modular-account/src/interfaces/erc4337/IEntryPoint.sol";
import { UserOperation } from "modular-account/src/interfaces/erc4337/UserOperation.sol";
import { PluginManifest } from "modular-account/src/interfaces/IPlugin.sol";
import { BasePlugin } from "modular-account/src/plugins/BasePlugin.sol";
import { IMultiOwnerPlugin } from "modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";
import { ContractOwner } from "modular-account/test/mocks/ContractOwner.sol";

import { WebauthnOwnerPlugin, SignatureWrapper, OwnersLib } from "../src/WebauthnOwnerPlugin.sol";

// solhint-disable func-name-mixedcase
contract MultiOwnerPluginTest is Test {
  using OwnersLib for address;
  using ECDSA for bytes32;

  WebauthnOwnerPlugin public plugin;
  IEntryPoint public entryPoint;

  bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
  address public accountA;
  address public b;

  address public owner1;
  address public owner2;
  address public owner3;
  address public ownerOfContractOwner;
  uint256 public ownerOfContractOwnerKey;
  ContractOwner public contractOwner;
  address[] public ownerArray;

  // Re-declare events for vm.expectEmit
  event OwnerUpdated(address indexed account, address[] addedOwners, address[] removedOwners);

  function setUp() external {
    plugin = new WebauthnOwnerPlugin();
    entryPoint = IEntryPoint(address(new EntryPoint()));

    accountA = address(new EntryPoint());
    b = makeAddr("b");
    owner1 = makeAddr("owner1");
    owner2 = makeAddr("owner2");
    owner3 = makeAddr("owner3");
    (ownerOfContractOwner, ownerOfContractOwnerKey) = makeAddrAndKey("ownerOfContractOwner");
    contractOwner = new ContractOwner(ownerOfContractOwner);

    // set up owners for accountA
    ownerArray = new address[](3);
    ownerArray[0] = owner2;
    ownerArray[1] = owner3;
    ownerArray[2] = owner1;

    vm.expectEmit(true, true, true, true);
    emit OwnerUpdated(accountA, ownerArray, new address[](0));
    vm.startPrank(accountA);
    plugin.onInstall(abi.encode(ownerArray));
  }

  function test_pluginManifest() external view {
    PluginManifest memory manifest = plugin.pluginManifest();
    // 4 execution functions
    assertEq(4, manifest.executionFunctions.length);
    // 5 native + 2 plugin exec func
    assertEq(7, manifest.userOpValidationFunctions.length);
    // 5 native + 2 plugin exec func + 2 plugin view func
    assertEq(9, manifest.runtimeValidationFunctions.length);
  }

  function test_onUninstall_success() external {
    // Populate the expected event using `plugin.ownersOf` instead of `ownerArray` to reverse the order of
    // owners.
    vm.expectEmit(true, true, true, true);
    emit OwnerUpdated(accountA, new address[](0), plugin.ownersOf(accountA));

    plugin.onUninstall(abi.encode(""));
    address[] memory returnedOwners = plugin.ownersOf(accountA);
    assertEq(0, returnedOwners.length);
  }

  function test_onInstall_success() external {
    address[] memory owners = new address[](1);
    owners[0] = owner1;

    vm.startPrank(address(contractOwner));
    plugin.onInstall(abi.encode(owners));
    address[] memory returnedOwners = plugin.ownersOf(address(contractOwner));
    assertEq(returnedOwners.length, 1);
    assertEq(returnedOwners[0], owner1);
    vm.stopPrank();
  }

  function test_eip712Domain() external view {
    assertEq(true, plugin.isOwnerOf(accountA, owner2));
    assertEq(false, plugin.isOwnerOf(accountA, address(contractOwner)));

    (
      bytes1 fields,
      string memory name,
      string memory version,
      uint256 chainId,
      address verifyingContract,
      bytes32 salt,
      uint256[] memory extensions
    ) = plugin.eip712Domain();
    assertEq(fields, hex"1f");
    assertEq(name, "Webauthn Owner Plugin");
    assertEq(version, "1.0.0");
    assertEq(chainId, block.chainid);
    assertEq(verifyingContract, accountA);
    assertEq(salt, bytes32(bytes20(address(plugin))));
    assertEq(extensions.length, 0);
  }

  function test_updateOwners_failWithEmptyOwners() external {
    vm.expectRevert(IMultiOwnerPlugin.EmptyOwnersNotAllowed.selector);
    plugin.updateOwners(new address[](0), ownerArray);
  }

  function test_updateOwners_failWithZeroAddressOwner() external {
    address[] memory ownersToAdd = new address[](2);

    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, address(0)));
    plugin.updateOwners(ownersToAdd, new address[](0));
  }

  function test_updateOwners_failWithDuplicatedAddresses() external {
    address[] memory ownersToAdd = new address[](2);
    ownersToAdd[0] = ownerOfContractOwner;
    ownersToAdd[1] = ownerOfContractOwner;

    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, ownerOfContractOwner));
    plugin.updateOwners(ownersToAdd, new address[](0));
  }

  function test_updateOwners_success() external {
    (address[] memory owners) = plugin.ownersOf(accountA);
    assertEq(ownerArray, owners);

    // remove should also work
    address[] memory ownersToRemove = new address[](2);
    ownersToRemove[0] = owner1;
    ownersToRemove[1] = owner2;

    vm.expectEmit(true, true, true, true);
    emit OwnerUpdated(accountA, new address[](0), ownersToRemove);

    plugin.updateOwners(new address[](0), ownersToRemove);

    (address[] memory newOwnerList) = plugin.ownersOf(accountA);
    assertEq(newOwnerList.length, 1);
    assertEq(newOwnerList[0], owner3);
  }

  function test_updateOwners_failWithNotExist() external {
    address[] memory ownersToRemove = new address[](1);
    ownersToRemove[0] = address(contractOwner);

    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.OwnerDoesNotExist.selector, address(contractOwner)));
    plugin.updateOwners(new address[](0), ownersToRemove);
  }

  function testFuzz_isValidSignature_EOAOwner(string memory salt, bytes32 digest) external {
    // range bound the possible set of priv keys
    (address signer, uint256 privateKey) = makeAddrAndKey(salt);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, plugin.getMessageHash(address(accountA), abi.encode(digest)));

    if (!plugin.isOwnerOf(accountA, signer)) {
      // sig check should fail
      assertEq(
        bytes4(0xFFFFFFFF), plugin.isValidSignature(digest, abi.encode(SignatureWrapper(0, abi.encodePacked(r, s, v))))
      );

      address[] memory ownersToAdd = new address[](1);
      ownersToAdd[0] = signer;
      plugin.updateOwners(ownersToAdd, new address[](0));
    }

    // sig check should pass
    assertEq(
      _1271_MAGIC_VALUE,
      plugin.isValidSignature(
        digest, abi.encode(SignatureWrapper(plugin.ownerIndexOf(accountA, signer.toBytes()), abi.encodePacked(r, s, v)))
      )
    );
  }

  function testFuzz_isValidSignature_ContractOwner(bytes32 digest) external {
    address[] memory ownersToAdd = new address[](1);
    ownersToAdd[0] = address(contractOwner);
    plugin.updateOwners(ownersToAdd, new address[](0));

    bytes32 messageDigest = plugin.getMessageHash(address(accountA), abi.encode(digest));
    bytes memory signature = abi.encode(
      SignatureWrapper(
        plugin.ownerIndexOf(accountA, address(contractOwner).toBytes()), contractOwner.sign(messageDigest)
      )
    );
    assertEq(_1271_MAGIC_VALUE, plugin.isValidSignature(digest, signature));
  }

  function testFuzz_isValidSignature_ContractOwnerWithEOAOwner(bytes32 digest) external {
    address[] memory ownersToAdd = new address[](1);
    ownersToAdd[0] = address(contractOwner);
    plugin.updateOwners(ownersToAdd, new address[](0));

    bytes32 messageDigest = plugin.getMessageHash(address(accountA), abi.encode(digest));
    // owner3 is the EOA Owner of the contractOwner
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerOfContractOwnerKey, messageDigest);
    bytes memory signature = abi.encode(
      SignatureWrapper(plugin.ownerIndexOf(accountA, address(contractOwner).toBytes()), abi.encodePacked(r, s, v))
    );
    assertEq(_1271_MAGIC_VALUE, plugin.isValidSignature(digest, signature));
  }

  function test_runtimeValidationFunction_OwnerOrSelf() external {
    // should pass with owner as sender
    plugin.runtimeValidationFunction(
      uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF), owner1, 0, ""
    );

    // should fail without owner as sender
    vm.expectRevert(IMultiOwnerPlugin.NotAuthorized.selector);
    plugin.runtimeValidationFunction(
      uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF), address(contractOwner), 0, ""
    );
  }

  function test_multiOwnerPlugin_sentinelIsNotOwner() external view {
    assertFalse(plugin.isOwnerOf(accountA, address(1)));
  }

  function testFuzz_userOpValidationFunction_ContractOwner(UserOperation memory userOp) external {
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
    bytes memory signature = contractOwner.sign(userOpHash.toEthSignedMessageHash());
    userOp.signature = abi.encode(SignatureWrapper(0, signature));

    // should fail without owner access
    uint256 resFail =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resFail, 1);

    address[] memory ownersToAdd = new address[](1);
    ownersToAdd[0] = address(contractOwner);
    plugin.updateOwners(ownersToAdd, new address[](0));

    userOp.signature =
      abi.encode(SignatureWrapper(plugin.ownerIndexOf(accountA, address(contractOwner).toBytes()), signature));
    // should pass with owner access
    uint256 resSuccess =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resSuccess, 0);
  }

  function testFuzz_userOpValidationFunction_ContractOwnerWithEOAOwner(UserOperation memory userOp) external {
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerOfContractOwnerKey, userOpHash.toEthSignedMessageHash());

    // sig cannot cover the whole user-op struct since user-op struct has sig field
    userOp.signature = abi.encode(SignatureWrapper(0, abi.encodePacked(r, s, v)));

    // should fail without owner access
    uint256 resFail =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resFail, 1);

    address[] memory ownersToAdd = new address[](1);
    ownersToAdd[0] = address(contractOwner);
    plugin.updateOwners(ownersToAdd, new address[](0));

    userOp.signature = abi.encode(
      SignatureWrapper(plugin.ownerIndexOf(accountA, address(contractOwner).toBytes()), abi.encodePacked(r, s, v))
    );
    // should pass with owner access
    uint256 resSuccess =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resSuccess, 0);
  }

  function testFuzz_userOpValidationFunction_EOAOwner(string memory salt, UserOperation memory userOp) external {
    // range bound the possible set of priv keys
    (address signer, uint256 privateKey) = makeAddrAndKey(salt);
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

    // sig cannot cover the whole user-op struct since user-op struct has sig field
    userOp.signature = abi.encode(SignatureWrapper(0, abi.encodePacked(r, s, v)));

    address[] memory ownersToAdd = new address[](1);
    ownersToAdd[0] = signer;

    // Only check that the signature should fail if the signer is not already an owner
    if (!plugin.isOwnerOf(accountA, signer)) {
      // should fail without owner access
      uint256 resFail = plugin.userOpValidationFunction(
        uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
      );
      assertEq(resFail, 1);
      // add signer to owner
      plugin.updateOwners(ownersToAdd, new address[](0));
    }

    userOp.signature =
      abi.encode(SignatureWrapper(plugin.ownerIndexOf(accountA, signer.toBytes()), abi.encodePacked(r, s, v)));
    // should pass with owner access
    uint256 resSuccess =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resSuccess, 0);
  }

  function test_pluginInitializeGuards() external {
    plugin.onUninstall(bytes(""));

    address[] memory addrArr = new address[](1);
    addrArr[0] = address(this);

    // can't transfer owner if not initialized yet
    vm.expectRevert(abi.encodeWithSelector(BasePlugin.NotInitialized.selector));
    plugin.updateOwners(addrArr, new address[](0));

    // can't onInstall twice
    plugin.onInstall(abi.encode(addrArr, new address[](0)));
    vm.expectRevert(abi.encodeWithSelector(BasePlugin.AlreadyInitialized.selector));
    plugin.onInstall(abi.encode(addrArr, new address[](0)));
  }
}
