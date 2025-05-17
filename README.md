# aura
magical, simple private currency in rust

## Thesis

* Monero is [actually broken](https://duke.hush.is/memos/6/), and it got broken because bulletproofs aren't ZK proofs
* Zcash has a vastly too tiny anonymity set
* IBC actually matters
* A validator set consisting of equally weighted nodes without staking and slashing can work just fine
* Inflation isn't needed
* Code AND supply need to be auditable
* Penumbra is a DEX, and stores some things in the clear.  Aura is a currency, and stores nothing in the clear.








## Approximate Layout

```
├── Cargo.toml (workspace definition)
├── aura
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs       (Parses subcommands, dispatches to modules)
│       ├── node_cmd.rs   (Logic for `aura node ...`)
│       ├── wallet_cmd.rs (Logic for `aura wallet ...`)
│       ├── utils_cmd.rs  (Logic for `aura utils ...`)
│       └── config.rs     (Handles config file loading/saving)
├── aura-core/
│   ├── Cargo.toml
│   └── src/            (ZKP circuits, note logic, tx structures, genesis parsing)
├── aura-node-lib/ (Name it something like this to avoid conflict with `node_cmd.rs`)
│   ├── Cargo.toml
│   └── src/            (Aura application logic that implements Malachite App trait,
│                        sled state management, RPC server logic, mempool)
├── aura-wallet-lib/
│   ├── Cargo.toml
│   └── src/            (Wallet key management, transaction construction (ZKP gen),
│                        blockchain scanning client logic, sled for local wallet DB)
└── malachite-core/ (As a dependency)
```
