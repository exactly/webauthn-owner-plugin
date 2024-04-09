// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.25;

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import { UpgradeableModularAccount, UUPSUpgradeable } from "modular-account/src/account/UpgradeableModularAccount.sol";
import { UserOperation } from "modular-account/src/interfaces/erc4337/UserOperation.sol";
import {
  ManifestAssociatedFunction,
  ManifestAssociatedFunctionType,
  ManifestFunction,
  PluginManifest,
  PluginMetadata,
  SelectorPermission
} from "modular-account/src/interfaces/IPlugin.sol";
import { IStandardExecutor } from "modular-account/src/interfaces/IStandardExecutor.sol";
import { SIG_VALIDATION_PASSED, SIG_VALIDATION_FAILED } from "modular-account/src/libraries/Constants.sol";
import { BasePlugin } from "modular-account/src/plugins/BasePlugin.sol";

import { ECDSA } from "solady/utils/ECDSA.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

import { WebAuthn } from "webauthn-sol/WebAuthn.sol";

import { OwnersLib, Owners } from "./OwnersLib.sol";
import { IWebauthnOwnerPlugin, IMultiOwnerPlugin, SignatureWrapper } from "./IWebauthnOwnerPlugin.sol";

contract WebauthnOwnerPlugin is BasePlugin, IWebauthnOwnerPlugin, IERC1271 {
  using SignatureCheckerLib for address;
  using OwnersLib for bytes32[2][64];
  using OwnersLib for bytes32[2];
  using OwnersLib for address[];
  using OwnersLib for Owners;
  using ECDSA for bytes32;

  string public constant NAME = "Webauthn Owner Plugin";
  string public constant AUTHOR = "Exactly";
  string public constant VERSION = "1.0.0";

  bytes32 private constant _TYPE_HASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
  bytes32 private constant _NAME_HASH = keccak256(bytes(NAME));
  bytes32 private constant _VERSION_HASH = keccak256(bytes(VERSION));
  bytes32 private immutable _SALT = bytes32(bytes20(address(this)));

  bytes32 private constant _MODULAR_ACCOUNT_TYPE_HASH = keccak256("AlchemyModularAccountMessage(bytes message)");

  mapping(address account => Owners owners) private _owners;

  /// @inheritdoc IMultiOwnerPlugin
  function updateOwners(address[] memory ownersToAdd, address[] memory ownersToRemove)
    external
    isInitialized(msg.sender)
  {
    updateOwnersBytes(ownersToAdd.toBytes(), ownersToRemove.toBytes());

    emit OwnerUpdated(msg.sender, ownersToAdd, ownersToRemove);
  }

  function updateOwnersBytes(bytes32[2][] memory ownersToAdd, bytes32[2][] memory ownersToRemove)
    public
    isInitialized(msg.sender)
  {
    Owners storage ownersStorage = _owners[msg.sender];
    bytes32[2][64] memory owners = ownersStorage.allFixed();

    for (uint256 i = 0; i < ownersToRemove.length; ++i) {
      if (!owners.contains(ownersToRemove[i])) revert OwnerDoesNotExist(ownersToRemove[i].toAddress());
    }

    uint256 ownerCount = ownersStorage.length;
    uint256 addIndex = 0;
    for (uint256 i = 0; i < ownerCount; ++i) {
      for (uint256 j = 0; j < ownersToRemove.length;) {
        if (owners[i].equals(ownersToRemove[j])) {
          --ownerCount;
          if (addIndex < ownersToAdd.length) {
            owners[i] = ownersToAdd[addIndex++];
          } else if (i < ownerCount) {
            owners[i] = owners[ownerCount];
            j = 0;
          }
          ownersStorage.data[i] = owners[i];
          if (ownerCount == 0) break;
        } else {
          ++j;
        }
      }
    }
    for (; addIndex < ownersToAdd.length; ++addIndex) {
      for (uint256 i = 0; i < ownerCount; ++i) {
        if (owners[i].equals(ownersToAdd[addIndex])) revert InvalidOwner(ownersToAdd[addIndex].toAddress());
      }
      owners[ownerCount] = ownersToAdd[addIndex];
      ownersStorage.data[ownerCount] = owners[ownerCount];
      ++ownerCount;
    }
    ownersStorage.length = ownerCount;

    if (ownerCount == 0) revert EmptyOwnersNotAllowed();

    emit OwnerUpdated(msg.sender, ownersToAdd, ownersToRemove);
  }

  /// @inheritdoc IMultiOwnerPlugin
  function eip712Domain()
    external
    view
    override
    returns (
      bytes1 fields,
      string memory name,
      string memory version,
      uint256 chainId,
      address verifyingContract,
      bytes32 salt,
      uint256[] memory extensions
    )
  {
    return (hex"1f", NAME, VERSION, block.chainid, msg.sender, _SALT, new uint256[](0));
  }

  /// @inheritdoc IERC1271
  function isValidSignature(bytes32 digest, bytes calldata signature) external view override returns (bytes4) {
    bytes32 messageHash = getMessageHash(msg.sender, abi.encode(digest));
    if (_validateSignature(msg.sender, messageHash, signature)) return this.isValidSignature.selector;
    return 0xffffffff;
  }

  /// @inheritdoc BasePlugin
  function _onInstall(bytes calldata data) internal override isNotInitialized(msg.sender) {
    (address[] memory initialOwners) = abi.decode(data, (address[]));
    if (initialOwners.length == 0) revert EmptyOwnersNotAllowed();
    _owners[msg.sender].push(initialOwners.toBytes());
    emit OwnerUpdated(msg.sender, initialOwners, new address[](0));
  }

  /// @inheritdoc BasePlugin
  function onUninstall(bytes calldata) external override {
    address[] memory owners = _owners[msg.sender].allAddresses();
    _owners[msg.sender].reset();
    emit OwnerUpdated(msg.sender, new address[](0), owners);
  }

  /// @inheritdoc BasePlugin
  function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
    external
    view
    override
    returns (uint256)
  {
    if (functionId == uint8(FunctionId.USER_OP_VALIDATION_OWNER)) {
      bytes32 messageHash = userOpHash.toEthSignedMessageHash();
      if (_validateSignature(msg.sender, messageHash, userOp.signature)) return SIG_VALIDATION_PASSED;
      return SIG_VALIDATION_FAILED;
    }
    revert NotImplemented(msg.sig, functionId);
  }

  /// @inheritdoc BasePlugin
  function runtimeValidationFunction(uint8 functionId, address sender, uint256, bytes calldata) external view override {
    if (functionId == uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)) {
      if (sender != msg.sender && !isOwnerOf(msg.sender, sender)) revert NotAuthorized();
      return;
    }
    revert NotImplemented(msg.sig, functionId);
  }

  /// @inheritdoc BasePlugin
  function pluginManifest() external pure override returns (PluginManifest memory manifest) {
    manifest.executionFunctions = new bytes4[](4);
    manifest.executionFunctions[0] = this.updateOwners.selector;
    manifest.executionFunctions[1] = this.eip712Domain.selector;
    manifest.executionFunctions[2] = this.isValidSignature.selector;
    manifest.executionFunctions[3] = this.updateOwnersBytes.selector;

    ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
      functionType: ManifestAssociatedFunctionType.SELF,
      functionId: uint8(FunctionId.USER_OP_VALIDATION_OWNER),
      dependencyIndex: 0
    });

    manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](7);
    manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
      executionSelector: this.updateOwners.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.execute.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.executeBatch.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
      executionSelector: UpgradeableModularAccount.installPlugin.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
      executionSelector: UpgradeableModularAccount.uninstallPlugin.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[5] = ManifestAssociatedFunction({
      executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[6] = ManifestAssociatedFunction({
      executionSelector: this.updateOwnersBytes.selector,
      associatedFunction: ownerUserOpValidationFunction
    });

    ManifestFunction memory ownerOrSelfRuntimeValidationFunction = ManifestFunction({
      functionType: ManifestAssociatedFunctionType.SELF,
      functionId: uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF),
      dependencyIndex: 0
    });
    ManifestFunction memory alwaysAllowFunction = ManifestFunction({
      functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
      functionId: 0,
      dependencyIndex: 0
    });

    manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](9);
    manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
      executionSelector: this.updateOwners.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.execute.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.executeBatch.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
      executionSelector: UpgradeableModularAccount.installPlugin.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
      executionSelector: UpgradeableModularAccount.uninstallPlugin.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[5] = ManifestAssociatedFunction({
      executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[6] = ManifestAssociatedFunction({
      executionSelector: this.isValidSignature.selector,
      associatedFunction: alwaysAllowFunction
    });
    manifest.runtimeValidationFunctions[7] = ManifestAssociatedFunction({
      executionSelector: this.eip712Domain.selector,
      associatedFunction: alwaysAllowFunction
    });
    manifest.runtimeValidationFunctions[8] = ManifestAssociatedFunction({
      executionSelector: this.updateOwnersBytes.selector,
      associatedFunction: alwaysAllowFunction
    });
  }

  /// @inheritdoc BasePlugin
  function pluginMetadata() external pure override returns (PluginMetadata memory metadata) {
    metadata.name = NAME;
    metadata.author = AUTHOR;
    metadata.version = VERSION;
    string memory modifyOwnershipPermission = "Modify Ownership";
    metadata.permissionDescriptors = new SelectorPermission[](2);
    metadata.permissionDescriptors[0] = SelectorPermission({
      functionSelector: this.updateOwners.selector,
      permissionDescription: modifyOwnershipPermission
    });
    metadata.permissionDescriptors[1] = SelectorPermission({
      functionSelector: this.updateOwnersBytes.selector,
      permissionDescription: modifyOwnershipPermission
    });
  }

  /// @inheritdoc BasePlugin
  function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
    return interfaceId == type(IWebauthnOwnerPlugin).interfaceId || interfaceId == type(IMultiOwnerPlugin).interfaceId
      || super.supportsInterface(interfaceId);
  }

  /// @inheritdoc IMultiOwnerPlugin
  function isOwnerOf(address account, address ownerToCheck) public view returns (bool) {
    return _owners[account].contains(ownerToCheck);
  }

  /// @inheritdoc IMultiOwnerPlugin
  function ownersOf(address account) external view returns (address[] memory owners) {
    owners = _owners[account].allAddresses();
  }

  function ownersBytesOf(address account) external view returns (bytes32[2][] memory owners) {
    owners = _owners[account].all();
  }

  function ownerIndexOf(address account, bytes32[2] calldata owner) external view returns (uint256 index) {
    Owners storage ownersStorage = _owners[account];
    uint256 ownerCount = ownersStorage.length;
    for (index = 0; index < ownerCount; ++index) {
      if (ownersStorage.data[index].equals(owner)) return index;
    }
    revert OwnerDoesNotExist(owner.toAddress());
  }

  /// @inheritdoc IMultiOwnerPlugin
  function encodeMessageData(address account, bytes memory message) public view override returns (bytes memory) {
    bytes32 messageHash = keccak256(abi.encode(_MODULAR_ACCOUNT_TYPE_HASH, keccak256(message)));
    return abi.encodePacked("\x19\x01", _domainSeparator(account), messageHash);
  }

  /// @inheritdoc IMultiOwnerPlugin
  function getMessageHash(address account, bytes memory message) public view override returns (bytes32) {
    return keccak256(encodeMessageData(account, message));
  }

  function _domainSeparator(address account) internal view returns (bytes32) {
    return keccak256(abi.encode(_TYPE_HASH, _NAME_HASH, _VERSION_HASH, block.chainid, account, _SALT));
  }

  function _validateSignature(address account, bytes32 message, bytes calldata signature) internal view returns (bool) {
    SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
    bytes32[2] memory owner = _owners[account].get(sigWrapper.ownerIndex);

    if (owner[1] == bytes32(0)) {
      if (uint256(bytes32(owner[0])) > type(uint160).max) revert InvalidEthereumAddressOwner(owner[0]);
      return address(uint160(uint256(owner[0]))).isValidSignatureNow(message, sigWrapper.signatureData);
    }

    return WebAuthn.verify({
      challenge: abi.encode(message),
      requireUV: false,
      webAuthnAuth: abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth)),
      x: uint256(owner[0]),
      y: uint256(owner[1])
    });
  }

  /// @inheritdoc BasePlugin
  function _isInitialized(address account) internal view override returns (bool) {
    return _owners[account].length != 0;
  }
}
