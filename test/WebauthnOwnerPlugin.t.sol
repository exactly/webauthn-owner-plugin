// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { Test, stdError } from "forge-std/Test.sol";

import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";

import { IEntryPoint } from "modular-account/src/interfaces/erc4337/IEntryPoint.sol";
import { IMultiOwnerPlugin } from "modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";
import { ContractOwner } from "modular-account/test/mocks/ContractOwner.sol";

import { PluginManifest, PluginMetadata } from "modular-account-libs/interfaces/IPlugin.sol";
import { UserOperation } from "modular-account-libs/interfaces/UserOperation.sol";
import { BasePlugin } from "modular-account-libs/plugins/BasePlugin.sol";

import { ECDSA } from "solady/utils/ECDSA.sol";

import { Utils, WebAuthnInfo } from "webauthn-sol/../test/Utils.sol";
import { WebAuthn } from "webauthn-sol/WebAuthn.sol";

import { ENTRYPOINT } from "../script/Factory.s.sol";
import { IndexOutOfBounds, OwnersLib } from "../src/OwnersLib.sol";
import { IWebauthnOwnerPlugin, MAX_OWNERS, PublicKey, WebauthnOwnerPlugin } from "../src/WebauthnOwnerPlugin.sol";

import { TestLib } from "./utils/TestLib.sol";

// solhint-disable func-name-mixedcase
contract MultiOwnerPluginTest is Test {
  using OwnersLib for PublicKey;
  using OwnersLib for address[];
  using TestLib for address;
  using Utils for uint256;
  using Utils for bytes32;
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
  PublicKey public passkeyOwner;
  uint256 public passkeyOwnerKey;
  address[] public ownerArray;

  function setUp() external {
    entryPoint = ENTRYPOINT;
    vm.etch(address(entryPoint), address(new EntryPoint()).code);
    plugin = new WebauthnOwnerPlugin();

    accountA = address(entryPoint);
    b = makeAddr("b");
    owner1 = makeAddr("owner1");
    owner2 = makeAddr("owner2");
    owner3 = makeAddr("owner3");
    (ownerOfContractOwner, ownerOfContractOwnerKey) = makeAddrAndKey("ownerOfContractOwner");
    contractOwner = new ContractOwner(ownerOfContractOwner);
    passkeyOwner = abi.decode(
      hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d",
      (PublicKey)
    );
    passkeyOwnerKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);

    // set up owners for accountA
    ownerArray = new address[](3);
    ownerArray[0] = owner2;
    ownerArray[1] = owner3;
    ownerArray[2] = owner1;

    vm.expectEmit(true, true, true, true);
    emit IWebauthnOwnerPlugin.OwnerUpdated(accountA, ownerArray.toPublicKeys(), new PublicKey[](0));
    vm.expectEmit(true, true, true, true);
    emit IMultiOwnerPlugin.OwnerUpdated(accountA, ownerArray, new address[](0));
    vm.startPrank(accountA);
    plugin.onInstall(abi.encode(ownerArray.toPublicKeys()));
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
    vm.expectEmit(true, true, true, true);
    emit IWebauthnOwnerPlugin.OwnerUpdated(accountA, new PublicKey[](0), plugin.ownersPublicKeysOf(accountA));
    vm.expectEmit(true, true, true, true);
    emit IMultiOwnerPlugin.OwnerUpdated(accountA, new address[](0), plugin.ownersOf(accountA));

    plugin.onUninstall(abi.encode(""));
    address[] memory returnedOwners = plugin.ownersOf(accountA);
    assertEq(0, returnedOwners.length);
  }

  function test_onInstall_success() external {
    address[] memory owners = new address[](1);
    owners[0] = owner1;

    vm.startPrank(address(contractOwner));
    plugin.onInstall(abi.encode(owners.toPublicKeys()));
    address[] memory returnedOwners = plugin.ownersOf(address(contractOwner));
    assertEq(returnedOwners.length, 1);
    assertEq(returnedOwners[0], owner1);
    vm.stopPrank();
  }

  function test_onInstall_failWithInvalidAddress() external {
    PublicKey[] memory owners = new PublicKey[](1);
    owners[0] = PublicKey(type(uint168).max, 0);

    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, owners[0].toAddress()));
    vm.startPrank(address(contractOwner));
    plugin.onInstall(abi.encode(owners));
    vm.stopPrank();
  }

  function test_onInstall_failWithEmptyOwners() external {
    vm.expectRevert(IMultiOwnerPlugin.EmptyOwnersNotAllowed.selector);
    vm.startPrank(address(contractOwner));
    plugin.onInstall(abi.encode(new PublicKey[](0)));
    vm.stopPrank();
  }

  function test_onInstall_failWithLimitExceeded() external {
    address[] memory owners = new address[](MAX_OWNERS + 1);
    for (uint160 i = 0; i < owners.length; ++i) {
      owners[i] = address(i + 1);
    }

    vm.expectRevert(stdError.indexOOBError);
    vm.startPrank(address(contractOwner));
    plugin.onInstall(abi.encode(owners.toPublicKeys()));
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
    emit IWebauthnOwnerPlugin.OwnerUpdated(accountA, new PublicKey[](0), ownersToRemove.toPublicKeys());
    vm.expectEmit(true, true, true, true);
    emit IMultiOwnerPlugin.OwnerUpdated(accountA, new address[](0), ownersToRemove);

    plugin.updateOwners(new address[](0), ownersToRemove);

    (address[] memory newOwnerList) = plugin.ownersOf(accountA);
    assertEq(newOwnerList.length, 1);
    assertEq(newOwnerList[0], owner3);
  }

  function test_updateOwners_addAndRemove() external {
    (address[] memory owners) = plugin.ownersOf(accountA);
    assertEq(ownerArray, owners);

    address[] memory ownersToRemove = new address[](3);
    ownersToRemove[0] = owner2;
    ownersToRemove[1] = owner3;
    ownersToRemove[2] = owner1;

    address[] memory ownersToAdd = new address[](2);
    ownersToAdd[0] = address(1);

    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, address(0)));
    plugin.updateOwners(ownersToAdd, ownersToRemove);

    ownersToAdd[1] = address(2);
    plugin.updateOwners(ownersToAdd, ownersToRemove);

    (address[] memory newOwnerList) = plugin.ownersOf(accountA);
    assertEq(newOwnerList.length, 2);
    assertEq(newOwnerList, ownersToAdd);
  }

  function test_updateOwners_failWithNotExist() external {
    address[] memory ownersToRemove = new address[](1);
    ownersToRemove[0] = address(contractOwner);

    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.OwnerDoesNotExist.selector, address(contractOwner)));
    plugin.updateOwners(new address[](0), ownersToRemove);
  }

  function test_updateOwners_failWithLimitExceeded() external {
    address[] memory ownersToAdd = new address[](MAX_OWNERS - ownerArray.length + 1);
    for (uint160 i = 0; i < ownersToAdd.length; ++i) {
      ownersToAdd[i] = address(i + 1);
    }

    vm.expectRevert(stdError.indexOOBError);
    plugin.updateOwners(ownersToAdd, new address[](0));
  }

  function test_updateOwnersPublicKeys_failWithInvalidAddress() external {
    PublicKey[] memory ownersToAdd = new PublicKey[](1);
    ownersToAdd[0] = PublicKey(type(uint168).max, 0);

    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, ownersToAdd[0].toAddress()));
    plugin.updateOwnersPublicKeys(ownersToAdd, new PublicKey[](0));
  }

  function testFuzz_isValidSignature_EOAOwner(string memory salt, bytes32 digest) external {
    // range bound the possible set of priv keys
    (address signer, uint256 privateKey) = makeAddrAndKey(salt);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, plugin.getMessageHash(address(accountA), abi.encode(digest)));

    if (!plugin.isOwnerOf(accountA, signer)) {
      // sig check should fail
      assertEq(
        bytes4(0xFFFFFFFF), plugin.isValidSignature(digest, abi.encodePacked(uint8(0), abi.encodePacked(r, s, v)))
      );

      address[] memory ownersToAdd = new address[](1);
      ownersToAdd[0] = signer;
      plugin.updateOwners(ownersToAdd, new address[](0));
    }

    // sig check should pass
    assertEq(
      _1271_MAGIC_VALUE,
      plugin.isValidSignature(
        digest, abi.encodePacked(plugin.ownerIndexOf(accountA, signer.toPublicKey()), abi.encodePacked(r, s, v))
      )
    );
  }

  function testFuzz_isValidSignature_PasskeyOwner(bytes32 digest) external {
    WebAuthnInfo memory webauthn = plugin.getMessageHash(address(accountA), abi.encode(digest)).getWebAuthnStruct();
    (bytes32 r, bytes32 s) = vm.signP256(passkeyOwnerKey, webauthn.messageHash);
    WebAuthn.WebAuthnAuth memory webauthnAuth = WebAuthn.WebAuthnAuth({
      authenticatorData: webauthn.authenticatorData,
      clientDataJSON: webauthn.clientDataJSON,
      typeIndex: 1,
      challengeIndex: 23,
      r: uint256(r),
      s: uint256(s).normalizeS()
    });

    assertEq(bytes4(0xFFFFFFFF), plugin.isValidSignature(digest, abi.encodePacked(uint8(0), abi.encode(webauthnAuth))));

    PublicKey[] memory ownersToAdd = new PublicKey[](1);
    ownersToAdd[0] = passkeyOwner;
    plugin.updateOwnersPublicKeys(ownersToAdd, new PublicKey[](0));

    // sig check should pass
    assertEq(
      _1271_MAGIC_VALUE,
      plugin.isValidSignature(
        digest, abi.encodePacked(plugin.ownerIndexOf(accountA, passkeyOwner), abi.encode(webauthnAuth))
      )
    );
  }

  function testFuzz_isValidSignature_ContractOwner(bytes32 digest) external {
    address[] memory ownersToAdd = new address[](1);
    ownersToAdd[0] = address(contractOwner);
    plugin.updateOwners(ownersToAdd, new address[](0));

    bytes32 messageDigest = plugin.getMessageHash(address(accountA), abi.encode(digest));
    bytes memory signature = abi.encodePacked(
      plugin.ownerIndexOf(accountA, address(contractOwner).toPublicKey()), contractOwner.sign(messageDigest)
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
    bytes memory signature =
      abi.encodePacked(plugin.ownerIndexOf(accountA, address(contractOwner).toPublicKey()), abi.encodePacked(r, s, v));
    assertEq(_1271_MAGIC_VALUE, plugin.isValidSignature(digest, signature));
  }

  function test_isValidSignature_failWithOutOfBounds() external {
    vm.expectRevert(IndexOutOfBounds.selector);
    plugin.isValidSignature("", abi.encodePacked(uint8(4), ""));
  }

  function test_isValidSignature_failMalformedAddress() external {
    vm.store(
      address(plugin),
      bytes32(uint256(keccak256(abi.encode(accountA, uint256(0)))) + 1),
      bytes32(uint256(type(uint160).max) + 1)
    );

    vm.expectRevert(
      abi.encodeWithSelector(
        IWebauthnOwnerPlugin.InvalidEthereumAddressOwner.selector, bytes32(uint256(type(uint160).max) + 1)
      )
    );
    plugin.isValidSignature("", abi.encodePacked(uint8(0), ""));
  }

  function testFuzz_runtimeValidationFunction_BadFunctionId(uint8 functionId) external {
    vm.assume(functionId != uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF));

    vm.expectRevert(
      abi.encodeWithSelector(
        BasePlugin.NotImplemented.selector, BasePlugin.runtimeValidationFunction.selector, functionId
      )
    );
    plugin.runtimeValidationFunction(functionId, address(0), 0, "");
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
    userOp.signature = abi.encodePacked(uint8(0), signature);

    // should fail without owner access
    uint256 resFail =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resFail, 1);

    address[] memory ownersToAdd = new address[](1);
    ownersToAdd[0] = address(contractOwner);
    plugin.updateOwners(ownersToAdd, new address[](0));

    userOp.signature = abi.encodePacked(plugin.ownerIndexOf(accountA, address(contractOwner).toPublicKey()), signature);
    // should pass with owner access
    uint256 resSuccess =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resSuccess, 0);
  }

  function testFuzz_userOpValidationFunction_ContractOwnerWithEOAOwner(UserOperation memory userOp) external {
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerOfContractOwnerKey, userOpHash.toEthSignedMessageHash());

    // sig cannot cover the whole user-op struct since user-op struct has sig field
    userOp.signature = abi.encodePacked(uint8(0), abi.encodePacked(r, s, v));

    // should fail without owner access
    uint256 resFail =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resFail, 1);

    address[] memory ownersToAdd = new address[](1);
    ownersToAdd[0] = address(contractOwner);
    plugin.updateOwners(ownersToAdd, new address[](0));

    userOp.signature =
      abi.encodePacked(plugin.ownerIndexOf(accountA, address(contractOwner).toPublicKey()), abi.encodePacked(r, s, v));
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
    userOp.signature = abi.encodePacked(uint8(0), abi.encodePacked(r, s, v));

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

    userOp.signature = abi.encodePacked(plugin.ownerIndexOf(accountA, signer.toPublicKey()), abi.encodePacked(r, s, v));
    // should pass with owner access
    uint256 resSuccess =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resSuccess, 0);
  }

  function testFuzz_userOpValidationFunction_PasskeyOwner(UserOperation memory userOp) external {
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
    WebAuthnInfo memory webauthn = userOpHash.toEthSignedMessageHash().getWebAuthnStruct();
    (bytes32 r, bytes32 s) = vm.signP256(passkeyOwnerKey, webauthn.messageHash);
    WebAuthn.WebAuthnAuth memory webauthnAuth = WebAuthn.WebAuthnAuth({
      authenticatorData: webauthn.authenticatorData,
      clientDataJSON: webauthn.clientDataJSON,
      typeIndex: 1,
      challengeIndex: 23,
      r: uint256(r),
      s: uint256(s).normalizeS()
    });

    // sig cannot cover the whole user-op struct since user-op struct has sig field
    userOp.signature = abi.encodePacked(uint8(0), abi.encode(webauthnAuth));

    // should fail without owner access
    uint256 resFail =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resFail, 1);

    PublicKey[] memory ownersToAdd = new PublicKey[](1);
    ownersToAdd[0] = passkeyOwner;
    plugin.updateOwnersPublicKeys(ownersToAdd, new PublicKey[](0));
    userOp.signature = abi.encodePacked(plugin.ownerIndexOf(accountA, passkeyOwner), abi.encode(webauthnAuth));

    // should pass with owner access
    uint256 resSuccess =
      plugin.userOpValidationFunction(uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    assertEq(resSuccess, 0);
  }

  function testFuzz_userOpValidationFunction_BadFunctionId(uint8 functionId) external {
    vm.assume(functionId != uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));

    UserOperation memory userOp;
    vm.expectRevert(
      abi.encodeWithSelector(
        BasePlugin.NotImplemented.selector, BasePlugin.userOpValidationFunction.selector, functionId
      )
    );
    plugin.userOpValidationFunction(functionId, userOp, 0);
  }

  function test_ownerIndexOf_failWithNotExist() external {
    vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.OwnerDoesNotExist.selector, address(0xb0b)));
    plugin.ownerIndexOf(accountA, address(0xb0b).toPublicKey());
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

  function test_pluginMetadata_success() external view {
    PluginMetadata memory metadata = plugin.pluginMetadata();

    assertEq(metadata.permissionDescriptors.length, 2);
    assertEq(metadata.permissionDescriptors[0].permissionDescription, "Modify Ownership");
    assertEq(metadata.permissionDescriptors[1].permissionDescription, "Modify Ownership");
    assertEq(metadata.permissionDescriptors[0].functionSelector, IMultiOwnerPlugin.updateOwners.selector);
    assertEq(metadata.permissionDescriptors[1].functionSelector, IWebauthnOwnerPlugin.updateOwnersPublicKeys.selector);
  }
}
