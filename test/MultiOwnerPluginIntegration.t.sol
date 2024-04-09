// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.25;

import { Test } from "forge-std/Test.sol";

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";

import { UpgradeableModularAccount } from "modular-account/src/account/UpgradeableModularAccount.sol";
import { MultiOwnerModularAccountFactory } from "modular-account/src/factory/MultiOwnerModularAccountFactory.sol";
import { IEntryPoint } from "modular-account/src/interfaces/erc4337/IEntryPoint.sol";
import { UserOperation } from "modular-account/src/interfaces/erc4337/UserOperation.sol";
import { IMultiOwnerPlugin } from "modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";
import { Counter } from "modular-account/test/mocks/Counter.sol";

import { WebauthnOwnerPlugin, SignatureWrapper, OwnersLib } from "../src/WebauthnOwnerPlugin.sol";

// solhint-disable func-name-mixedcase
contract MultiOwnerPluginIntegration is Test {
  using OwnersLib for address;
  using ECDSA for bytes32;

  // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
  bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
  bytes4 internal constant _1271_MAGIC_VALUE_FAILURE = 0xffffffff;

  IEntryPoint public entryPoint;
  WebauthnOwnerPlugin public plugin;
  MultiOwnerModularAccountFactory public factory;

  Counter public counter;
  address payable public beneficiary;
  address public user1;
  uint256 public user1Key;

  address public owner1;
  uint256 public owner1Key;
  UpgradeableModularAccount public account;

  address public owner2;
  uint256 public owner2Key;

  address[] public owners;

  function setUp() external {
    // setup dependencies and helper contract
    counter = new Counter();
    entryPoint = IEntryPoint(address(new EntryPoint()));
    beneficiary = payable(makeAddr("beneficiary"));
    (user1, user1Key) = makeAddrAndKey("user1");
    (owner1, owner1Key) = makeAddrAndKey("owner1");
    (owner2, owner2Key) = makeAddrAndKey("owner2");

    // setup plugins and factory
    plugin = new WebauthnOwnerPlugin();
    factory = new MultiOwnerModularAccountFactory(
      address(this),
      address(plugin),
      address(new UpgradeableModularAccount(IEntryPoint(address(entryPoint)))),
      keccak256(abi.encode(plugin.pluginManifest())),
      entryPoint
    );

    // setup account with MultiOwnerModularAccountFactory
    owners = new address[](2);
    owners[0] = owner1 > owner2 ? owner2 : owner1;
    owners[1] = owner2 > owner1 ? owner2 : owner1;
    account = UpgradeableModularAccount(payable(factory.getAddress(0, owners)));
    vm.label(address(account), "account");
    vm.deal(address(account), 100 ether);
    factory.createAccount(0, owners);
  }

  function test_ownerPlugin_successInstallation() external view {
    assertTrue(plugin.isOwnerOf(address(account), owner1));
    assertTrue(plugin.isOwnerOf(address(account), owner2));
    assertEq(owners, plugin.ownersOf(address(account)));
  }

  function test_runtimeValidation_alwaysAllow_isValidSignature() external view {
    bytes32 digest = bytes32("digest");
    bytes32 messageDigest = plugin.getMessageHash(address(account), abi.encode(digest));
    bytes memory signature;

    {
      // should fail for sig from owner1 due to wrongly encode message
      bytes32 messageDigestBad =
        keccak256(abi.encodePacked("\x19\x01", keccak256(abi.encode(user1, block.chainid)), abi.encode(digest)));
      (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(owner1Key, messageDigestBad);
      signature = abi.encode(
        SignatureWrapper(plugin.ownerIndexOf(address(account), owner1.toBytes()), abi.encodePacked(r0, s0, v0))
      );
      assertEq(_1271_MAGIC_VALUE_FAILURE, IERC1271(address(account)).isValidSignature(digest, signature));
    }

    // should pass for sig from owner1
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, messageDigest);
    signature =
      abi.encode(SignatureWrapper(plugin.ownerIndexOf(address(account), owner1.toBytes()), abi.encodePacked(r, s, v)));
    assertEq(_1271_MAGIC_VALUE, IERC1271(address(account)).isValidSignature(digest, signature));

    // should pass for sig from owner2
    (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(owner2Key, messageDigest);
    signature = abi.encode(
      SignatureWrapper(plugin.ownerIndexOf(address(account), owner2.toBytes()), abi.encodePacked(r1, s1, v1))
    );
    assertEq(_1271_MAGIC_VALUE, IERC1271(address(account)).isValidSignature(digest, signature));

    // should fail for sig NOT from owner
    (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(user1Key, messageDigest);
    signature = abi.encode(
      SignatureWrapper(plugin.ownerIndexOf(address(account), owner1.toBytes()), abi.encodePacked(r2, s2, v2))
    );
    assertEq(_1271_MAGIC_VALUE_FAILURE, IERC1271(address(account)).isValidSignature(digest, signature));
  }

  function test_runtimeValidation_ownerOrSelf_standardExecute() external {
    // should send 1 ETH to user1 by owner
    uint256 startBal = user1.balance;
    vm.startPrank(owner1);
    account.execute(user1, 1 ether, "");
    assertEq(1 ether, user1.balance - startBal);

    // should NOT send 1 ETH to user1 by non-owner
    startBal = user1.balance;
    vm.startPrank(user1);
    vm.expectRevert(
      abi.encodeWithSelector(
        UpgradeableModularAccount.RuntimeValidationFunctionReverted.selector,
        plugin,
        IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF,
        abi.encodeWithSelector(IMultiOwnerPlugin.NotAuthorized.selector)
      )
    );
    account.execute(user1, 1 ether, "");
    assertEq(0 ether, user1.balance - startBal);
  }

  function test_userOpValidation_owner_standardExecute() external {
    UserOperation memory userOp = UserOperation({
      sender: address(account),
      nonce: 0,
      initCode: "",
      callData: abi.encodeCall(account.execute, (user1, 1 ether, "")),
      callGasLimit: 50_000,
      verificationGasLimit: 1_200_000,
      preVerificationGas: 0,
      maxFeePerGas: 1,
      maxPriorityFeePerGas: 1,
      paymasterAndData: "",
      signature: ""
    });

    // should send 1 ETH to user1 by owner
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
    userOp.signature =
      abi.encode(SignatureWrapper(plugin.ownerIndexOf(address(account), owner1.toBytes()), abi.encodePacked(r, s, v)));
    UserOperation[] memory userOps = new UserOperation[](1);
    userOps[0] = userOp;
    uint256 startBal = user1.balance;
    entryPoint.handleOps(userOps, beneficiary);
    assertEq(1 ether, user1.balance - startBal);

    // should NOT send 1 ETH to user1 by non-owner
    userOp.nonce++;
    bytes32 userOpHash2 = entryPoint.getUserOpHash(userOp);
    (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(user1Key, userOpHash2.toEthSignedMessageHash());
    userOp.signature = abi.encode(
      SignatureWrapper(plugin.ownerIndexOf(address(account), owner1.toBytes()), abi.encodePacked(r2, s2, v2))
    );
    UserOperation[] memory userOps2 = new UserOperation[](1);
    userOps2[0] = userOp;
    startBal = user1.balance;
    vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
    entryPoint.handleOps(userOps2, beneficiary);
    assertEq(0 ether, user1.balance - startBal);
  }
}
