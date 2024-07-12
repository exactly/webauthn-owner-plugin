# Webauthn Owner Plugin

This repository contains code for an ERC-6900 compliant plugin where one or more
EOA accounts, ERC-1271 compliant contracts, or P256 passkeys can be owners of
the account. Its core features include:

- Enable ECDSA verification of signatures, standard EOA signature verification.
- Enable ERC-1271 signature verification, standard contract owner signature
  verification.
- Enable Webauthn verification, secp256r1 (P256) passkey signatures verification.
- Multiple equal owners who have the same root access to account.
- Implements EIP-712.
- By default, owner validation is added for most of the account's native functions,
  including:
  - `installPlugin`/ `uninstallPlugin`
  - `upgradeToAndCall`
  - `execute` / `executeBatch`

This plugin is optimized for Ethereum layer 2 rollup chains but will work on all
EVM chains. Signature verification always attempts to use the RIP-7212 precompile
and, if this fails, falls back to using FreshCryptoLib.
It conforms to these ERC versions:

- ERC-4337: [0.6.0](https://github.com/eth-infinitism/account-abstraction/blob/releases/v0.6/eip/EIPS/eip-4337.md)
- ERC-6900: [0.7.0](https://github.com/erc6900/reference-implementation/blob/v0.7.x/standard/ERCs/erc-6900.md)

> [!IMPORTANT]
>
> - FreshCryptoLib uses the `ModExp` precompile (`address(0x05)`), which is not supported
>   on some chains, such as [Polygon zkEVM](https://www.rollup.codes/polygon-zkevm#precompiled-contracts).
>   This plugin will not work on such chains, unless they support the RIP-7212 precompile.
> - When attempting to use the RIP-7212 precompile, the plugin will call the precompile
>   (`address(0x100)`). However, since signature validation might be called during
>   a user operation validation phase, it can violate ERC-7562 [validation rule OP-041](https://eips.ethereum.org/EIPS/eip-7562#validation-rules)
>   on networks that don't support the RIP-7212 precompile. Therefore, this plugin
>   won't be compatible with most bundlers on such networks.

## Developing

After cloning the repo, run the tests using Forge, from [Foundry](https://github.com/foundry-rs/foundry)

```bash
forge test
```

### Static Analysis

To run the static analysis tools, install the Python dependencies in `requirements.txt`
and the JavaScript dependencies using any [_npm-compatible_](https://bun.sh/)
package manager:

```bash
pip install -r requirements.txt
bun install # or npm install
```

Then run the full suite of tests, including static analysis, formatting,
and gas checking:

```bash
bun run test # or npm run test
```

## Influences

Much of the code in this repository started from Alchemy's [Multi Owner Plugin](https://github.com/alchemyplatform/modular-account/blob/develop/src/plugins/owner/MultiOwnerPlugin.sol)
implementation. It was also influenced by Coinbase's [Smart Wallet](https://github.com/coinbase/smart-wallet).
