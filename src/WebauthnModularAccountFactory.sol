// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { Ownable } from "openzeppelin-contracts/contracts/access/Ownable.sol";
import { Ownable2Step } from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";

import { FactoryHelpers } from "modular-account/src/helpers/FactoryHelpers.sol";
import { IAccountInitializable } from "modular-account/src/interfaces/IAccountInitializable.sol";
import { IEntryPoint } from "modular-account/src/interfaces/erc4337/IEntryPoint.sol";
import { IMultiOwnerPlugin } from "modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";

import { LibClone } from "solady/utils/LibClone.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

import { MAX_OWNERS, PublicKey } from "./IWebauthnOwnerPlugin.sol";
import { OwnersLib } from "./OwnersLib.sol";

/// @title Webauthn Owner Plugin Modular Account Factory
/// @author Exactly
/// @author Modified from Alchemy's MultiOwnerModularAccountFactory
/// @notice Factory for upgradeable modular accounts with WebauthnOwnerPlugin installed.
/// @dev There is a reliance on the assumption that the plugin manifest will remain static, following ERC-6900. If
/// this assumption is broken then account deployments would be bricked.
contract WebauthnModularAccountFactory is Ownable2Step {
  using SafeTransferLib for address payable;
  using SafeTransferLib for address;
  using FactoryHelpers for uint256;
  using OwnersLib for PublicKey[MAX_OWNERS];
  using OwnersLib for PublicKey[];
  using OwnersLib for PublicKey;
  using LibClone for address;

  IEntryPoint public immutable ENTRYPOINT;
  address public immutable WEBAUTHN_OWNER_PLUGIN;
  address public immutable IMPL;
  bytes32 internal immutable _WEBAUTHN_OWNER_PLUGIN_MANIFEST_HASH;

  /// @notice Constructor for the factory
  constructor(
    address owner,
    address webauthnOwnerPlugin,
    address implementation,
    bytes32 webauthnOwnerPluginManifestHash,
    IEntryPoint entryPoint
  ) Ownable(owner) {
    if (webauthnOwnerPlugin == address(0) || implementation == address(0) || address(entryPoint) == address(0)) {
      revert InvalidAction();
    }

    WEBAUTHN_OWNER_PLUGIN = webauthnOwnerPlugin;
    IMPL = implementation;
    _WEBAUTHN_OWNER_PLUGIN_MANIFEST_HASH = webauthnOwnerPluginManifestHash;
    ENTRYPOINT = entryPoint;
  }

  /// @notice Allow contract to receive native currency
  receive() external payable { }

  /// @notice Create a modular smart contract account
  /// @dev Account address depends on salt, impl addr, plugins and plugin init data
  /// @dev The owner array must be in strictly ascending order and not include the 0 address.
  /// @param salt salt for create2
  /// @param owners address array of the owners
  function createAccount(uint256 salt, PublicKey[] calldata owners) external returns (address accountAddress) {
    bytes memory ownerBytes = abi.encode(owners);
    bytes32 combinedSalt = salt.getCombinedSalt(ownerBytes);
    bool alreadyDeployed;
    (alreadyDeployed, accountAddress) = IMPL.createDeterministicERC1967(combinedSalt);

    if (!alreadyDeployed) _initializeAccount(IAccountInitializable(accountAddress), ownerBytes);
  }

  /// @notice Add stake to an entry point
  /// @dev only callable by owner
  /// @param unstakeDelay unstake delay for the stake
  /// @param amount amount of native currency to stake
  function addStake(uint32 unstakeDelay, uint256 amount) external payable onlyOwner {
    ENTRYPOINT.addStake{ value: amount }(unstakeDelay);
  }

  /// @notice Start unlocking stake for an entry point
  /// @dev only callable by owner
  function unlockStake() external onlyOwner {
    ENTRYPOINT.unlockStake();
  }

  /// @notice Withdraw stake from an entry point
  /// @dev only callable by owner
  /// @param to address to send native currency to
  function withdrawStake(address payable to) external onlyOwner {
    ENTRYPOINT.withdrawStake(to);
  }

  /// @notice Withdraw funds from this contract
  /// @dev can withdraw stuck erc20s or native currency
  /// @param to address to send erc20s or native currency to
  /// @param token address of the token to withdraw, 0 address for native currency
  /// @param amount amount of the token to withdraw in case of rebasing tokens
  function withdraw(address payable to, address token, uint256 amount) external onlyOwner {
    if (token == address(0)) {
      to.safeTransferETH(address(this).balance);
    } else {
      token.safeTransfer(to, amount);
    }
  }

  /// @notice Getter for counterfactual address based on input params
  /// @dev The owner array must be in strictly ascending order and not include the 0 address.
  /// @param salt salt for additional entropy for create2
  /// @param owners array of addresses of the owner
  /// @return address of counterfactual account
  function getAddress(uint256 salt, PublicKey[] calldata owners) external view returns (address) {
    // Array can't be empty.
    if (owners.length == 0) revert IMultiOwnerPlugin.EmptyOwnersNotAllowed();

    if (owners.length > MAX_OWNERS) revert OwnersLimitExceeded();

    address previousOwnerAddress;
    for (uint256 i = 0; i < owners.length; ++i) {
      address ownerAddress = owners[i].toAddress();
      if (ownerAddress <= previousOwnerAddress) revert IMultiOwnerPlugin.InvalidOwner(ownerAddress);
      previousOwnerAddress = ownerAddress;
    }

    return IMPL.predictDeterministicAddressERC1967(salt.getCombinedSalt(abi.encode(owners)), address(this));
  }

  /// @notice Overriding to disable renounce ownership in Ownable
  function renounceOwnership() public view override onlyOwner {
    revert InvalidAction();
  }

  function _initializeAccount(IAccountInitializable account, bytes memory owners) internal virtual {
    address[] memory plugins = new address[](1);
    plugins[0] = WEBAUTHN_OWNER_PLUGIN;

    bytes32[] memory manifestHashes = new bytes32[](1);
    manifestHashes[0] = _WEBAUTHN_OWNER_PLUGIN_MANIFEST_HASH;

    bytes[] memory initBytes = new bytes[](1);
    initBytes[0] = owners;

    account.initialize(plugins, abi.encode(manifestHashes, initBytes));
  }
}

error InvalidAction();
error OwnersLimitExceeded();
