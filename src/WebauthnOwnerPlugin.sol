// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.20;

import { IMultiOwnerPlugin } from "modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";

import {
  ManifestAssociatedFunction,
  ManifestAssociatedFunctionType,
  ManifestFunction,
  PluginManifest,
  PluginMetadata,
  SelectorPermission
} from "modular-account-libs/interfaces/IPlugin.sol";
import { IPluginManager } from "modular-account-libs/interfaces/IPluginManager.sol";
import { IStandardExecutor } from "modular-account-libs/interfaces/IStandardExecutor.sol";
import { UserOperation } from "modular-account-libs/interfaces/UserOperation.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_PASSED } from "modular-account-libs/libraries/Constants.sol";
import { BasePlugin } from "modular-account-libs/plugins/BasePlugin.sol";

import { IERC1271 } from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";

import { ECDSA } from "solady/utils/ECDSA.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { UUPSUpgradeable } from "solady/utils/UUPSUpgradeable.sol";

import { WebAuthn } from "webauthn-sol/WebAuthn.sol";

import { IWebauthnOwnerPlugin, MAX_OWNERS, PublicKey } from "./IWebauthnOwnerPlugin.sol";
import { Owners, OwnersLib } from "./OwnersLib.sol";

contract WebauthnOwnerPlugin is BasePlugin, IWebauthnOwnerPlugin, IERC1271 {
  using SignatureCheckerLib for address;
  using OwnersLib for PublicKey[MAX_OWNERS];
  using OwnersLib for PublicKey[];
  using OwnersLib for PublicKey;
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
    updateOwnersPublicKeys(ownersToAdd.toPublicKeys(), ownersToRemove.toPublicKeys());

    emit OwnerUpdated(msg.sender, ownersToAdd, ownersToRemove);
  }

  function updateOwnersPublicKeys(PublicKey[] memory ownersToAdd, PublicKey[] memory ownersToRemove)
    public
    isInitialized(msg.sender)
  {
    Owners storage owners = _owners[msg.sender];
    (uint256 ownerCount, PublicKey[MAX_OWNERS] memory keys) = owners.all64();
    uint256 addIndex = 0;
    for (uint256 removeIndex = 0; removeIndex < ownersToRemove.length; ++removeIndex) {
      uint256 ownerIndex = keys.find(ownersToRemove[removeIndex], ownerCount);
      if (ownerIndex == type(uint256).max) revert OwnerDoesNotExist(ownersToRemove[removeIndex].toAddress());
      if (--ownerCount == 0) break;
      keys[ownerIndex] = addIndex < ownersToAdd.length ? ownersToAdd[addIndex++] : keys[ownerCount];
      owners.publicKeys[ownerIndex] = keys[ownerIndex];
    }
    for (; addIndex < ownersToAdd.length; ++addIndex) {
      if (ownersToAdd[addIndex].isInvalid() || keys.contains(ownersToAdd[addIndex], ownerCount)) {
        revert InvalidOwner(ownersToAdd[addIndex].toAddress());
      }
      keys[ownerCount] = ownersToAdd[addIndex];
      owners.publicKeys[ownerCount] = keys[ownerCount];
      ++ownerCount;
    }
    if (ownerCount > MAX_OWNERS) revert OwnersLimitExceeded();
    if (ownerCount == 0) revert EmptyOwnersNotAllowed();

    owners.length = ownerCount;

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
    (PublicKey[] memory initialOwners) = abi.decode(data, (PublicKey[]));
    if (initialOwners.length == 0) revert EmptyOwnersNotAllowed();
    if (initialOwners.length > MAX_OWNERS) revert OwnersLimitExceeded();

    uint256 count = 0;
    address previousOwnerAddress;
    PublicKey[MAX_OWNERS] memory keys;
    Owners storage owners = _owners[msg.sender];
    for (; count < initialOwners.length; ++count) {
      address ownerAddress = initialOwners[count].toAddress();
      if (initialOwners[count].isInvalid() || ownerAddress <= previousOwnerAddress) revert InvalidOwner(ownerAddress);
      keys[count] = initialOwners[count];
      owners.publicKeys[count] = keys[count];
      previousOwnerAddress = ownerAddress;
    }
    owners.length = count;

    emit OwnerUpdated(msg.sender, initialOwners, new PublicKey[](0));
    emit OwnerUpdated(msg.sender, initialOwners.toAddresses(), new address[](0));
  }

  /// @inheritdoc BasePlugin
  function onUninstall(bytes calldata) external override {
    PublicKey[] memory owners = _owners[msg.sender].all();
    _owners[msg.sender].length = 0;
    emit OwnerUpdated(msg.sender, new PublicKey[](0), owners);
    emit OwnerUpdated(msg.sender, new address[](0), owners.toAddresses());
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
    manifest.executionFunctions[3] = this.updateOwnersPublicKeys.selector;

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
      executionSelector: IPluginManager.installPlugin.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
      executionSelector: IPluginManager.uninstallPlugin.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[5] = ManifestAssociatedFunction({
      executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[6] = ManifestAssociatedFunction({
      executionSelector: this.updateOwnersPublicKeys.selector,
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
      executionSelector: this.updateOwnersPublicKeys.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.execute.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.executeBatch.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
      executionSelector: IPluginManager.installPlugin.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[5] = ManifestAssociatedFunction({
      executionSelector: IPluginManager.uninstallPlugin.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[6] = ManifestAssociatedFunction({
      executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[7] = ManifestAssociatedFunction({
      executionSelector: this.isValidSignature.selector,
      associatedFunction: alwaysAllowFunction
    });
    manifest.runtimeValidationFunctions[8] = ManifestAssociatedFunction({
      executionSelector: this.eip712Domain.selector,
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
      functionSelector: this.updateOwnersPublicKeys.selector,
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

  function ownersPublicKeysOf(address account) external view returns (PublicKey[] memory owners) {
    owners = _owners[account].all();
  }

  function ownerIndexOf(address account, PublicKey calldata owner) external view returns (uint8 index) {
    Owners storage owners = _owners[account];
    uint256 ownerCount = owners.length;
    for (index = 0; index < ownerCount; ++index) {
      if (owners.publicKeys[index].equals(owner)) return index;
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

  /// @dev Webauthn public keys with `y` as 0 are not supported, as they will be treated as Ethereum addresses.
  function _validateSignature(address account, bytes32 message, bytes calldata signature) internal view returns (bool) {
    PublicKey memory owner = _owners[account].get(uint8(signature[0]));

    if (owner.y == 0) {
      if (owner.x > type(uint160).max) revert InvalidEthereumAddressOwner(bytes32(owner.x));
      return address(uint160(owner.x)).isValidSignatureNowCalldata(message, signature[1:]);
    }

    return WebAuthn.verify({
      challenge: abi.encode(message),
      requireUV: false,
      webAuthnAuth: abi.decode(signature[1:], (WebAuthn.WebAuthnAuth)),
      x: owner.x,
      y: owner.y
    });
  }

  /// @inheritdoc BasePlugin
  function _isInitialized(address account) internal view override returns (bool) {
    return _owners[account].length != 0;
  }
}
