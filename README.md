# aura

magical, simple private currency in rust

## Thesis

* Monero is [actually broken](https://duke.hush.is/memos/6/), and it got broken because bulletproofs aren't ZK proofs
* Transparency and privacy don't mix
* Reorgs are essentially a bug, so we're using tendermint consensus
* IBC actually matters
* Slashing isn't needed
* Inflation isn't needed
* Relatively high tx fees are needed
* Code AND supply need to be auditable
* Aura is a currency, and stores nothing in the clear

## Local single node devnet

### set up keys


#### Single Node Testnet

```bash
cargo run -p aura -- single-node-testnet
```

#### Multi-Node Testnet

```bash
cargo run --bin aura -- multi-node-testnet --nodes 100
```



### config file

```
moniker = "solo-validator"
home    = "."
genesis_file            = "genesis.json"          # see next step
priv_validator_key_file = "node_key.json"         # we just created it
node_key_file           = "node_key.json"         # same file is fine

[p2p]
listen_addr   = "/ip4/0.0.0.0/tcp/26656"
external_addr = ""
seeds         = []

[consensus]
# → all values are the defaults Malachite expects
timeout_propose_ms   = 3000
timeout_prevote_ms   = 1000
timeout_precommit_ms = 1000
timeout_commit_ms    = 1000
```

## Using Malachite

Aura connects to the Malachite consensus engine through the
[malachitebft_app_channel] crate.  The node expects a `malachite.toml` file in
its home directory with standard Malachite configuration values.

### Channel messages

The implementation currently handles the following message types:

```
ConsensusReady
StartedRound
GetValue
ExtendVote
VerifyVoteExtension
RestreamProposal
GetHistoryMinHeight
ReceivedProposalPart
GetValidatorSet
Decided
GetDecidedValue
ProcessSyncedValue
```


## Status

For the love of god don't use this right now.  It is:

* Not working
* Not audited
* Not finished
* Not secure

But if you want to contribute, I'd love it!

## Chain State

Unless we choose another path, we'll be using the bech32 side (cosmos side) of "unicornandmemes.com".

* My Snapshot
  * QmNLocWsww2QgXGawfMPj8tn9ggzEt4dbiywAKiFjgGQhr
* Unity's Snapshot
  * QmNyt5bh6KRgPukeH2XScdRnycn4pxHVyAdMKgrHVMktGX
 
Instead of forcing users to go out and get genesis on their own, Aura will automagically download a snapshot, do a bech32 conversion, and create genesis on its own.  This is designed to be a very easy process for cosmos-sdk blockchains, and may support Solana in the future.

When running `aura node start` the client checks for `~/.aura/genesis.json`.  If
it doesn't exist the snapshot referenced above is fetched from IPFS, all
`unicorn` bech32 addresses are converted to the `whiteaura` prefix and any
`uwunicorn` denominations are renamed to `uaura`.  The resulting genesis file is
written to the configured location so new nodes can join the testnet with a
single command.

## Approximate Layout

```txt
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
