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

> [!CAUTION]
> The code in this repository and its dependencies are still under audit.
  It is not yet recommended for production use.

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
