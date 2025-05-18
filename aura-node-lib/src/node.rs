use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex}; // Corrected Mutex import

use async_trait::async_trait;
use eyre::eyre; // For easier error creation
use tracing::{Instrument, debug, error, info, warn};

use crate::config::AuraNodeConfig as AuraAppNodeConfig;
use crate::state::{
    AuraState, Block as AuraInternalBlock, ExecTxResult, ValidatorUpdate as AuraValidatorUpdate,
};
// use crate::Result as AuraLibResult; // Not used directly in this file after changes
// use crate::Error as AuraError; // Not used directly in this file after changes

// --- Malachite App Channel Imports (Corrected based on tutorial & common patterns) ---
use malachitebft_app_channel::{
    AppMsg,
    Channels,
    EngineHandle,
    RxEvent,
    TxEvent,
    // start_engine is directly under malachitebft_app_channel
    app::{
        ConsensusMsg,
        Context as MalachiteAppChannelContext, // Renamed for clarity
        NetworkMsg,
        Node as MalachiteAppChannelNode,
        NodeHandle as MalachiteAppChannelNodeHandle,
        types::{
            LocallyProposedValue, // Added this
            NilOrVal,
            ProposedValue,
            Round,
            ValueId, // Added ProposedValue
            core::{
                Address as MalachiteAddressTrait, Extension as MalachiteExtensionTrait,
                Height as MalachiteHeightTrait, Proposal as MalachiteProposalTrait,
                ProposalPart as MalachiteProposalPartTrait,
                SigningScheme as MalachiteSigningSchemeTrait, Validator as MalachiteValidatorTrait,
                ValidatorSet as MalachiteValidatorSetTrait, Value as MalachiteValueTrait,
                Vote as MalachiteVoteTrait,
            },
        },
    },
};

// --- Malachite Config (as provided) ---
use malachitebft_config::{
    ConsensusConfig as MalachiteBftConsensusConfig, P2pConfig as MalachiteBftP2pConfig,
};

// --- Malachite Core Types ---
use malachitebft_core_types::{
    // Types for Context often come from here or malachitebft_test
    // For example, if MalachiteAppChannelContext requires Ctx: malachitebft_core_types::Context
    Context as MalachiteCoreContextTrait, // The more fundamental Context trait
    // If specific types like Height, Address are needed from core_types directly:
    // height::Height as MalachiteCoreHeight, // Example
    NodeKey, // For P2P identity
};

// --- Malachite Test Types (for concrete implementations of traits) ---
use malachitebft_test::{
    Address as TestAddress,
    Context as TestContext, // A concrete impl of MalachiteCoreContextTrait
    Ed25519Provider,
    Extension as TestExtension,
    Genesis as TestGenesis,
    Height as TestHeight,
    Keypair as TestKeypair,
    PrivateKey as TestPrivateKey, // Validator signing key (Ed25519 based)
    Proposal as TestProposal,
    ProposalPart as TestProposalPart, // Concrete proposal part type
    PublicKey as TestPublicKey,
    Validator as TestValidator,
    ValidatorSet as TestValidatorSet,
    Value as TestValue, // Simple u64 value
    Vote as TestVote,
    codec::proto::ProtobufCodec, // Codec implementation
    // types for streaming might be here or in core_types / app_channel
    streaming::StreamContent, // Corrected path from clippy hint
};

// --- Placeholder for Malachite's Top-Level Config ---
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MalachiteTopLevelConfig {
    pub moniker: String,
    pub home: PathBuf,
    pub genesis_file: PathBuf,
    pub priv_validator_key_file: PathBuf,
    pub node_key_file: PathBuf, // Added for explicit P2P node key
    pub p2p: MalachiteBftP2pConfig,
    pub consensus: MalachiteBftConsensusConfig,
    // pub log_level: String, // Example from Tendermint/CometBFT
    // pub rpc_laddr: String, // Example
}
impl MalachiteTopLevelConfig {
    pub fn load_toml_file<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let config_str = fs::read_to_string(path.as_ref())?;
        toml::from_str(&config_str).map_err(anyhow::Error::from)
    }
}

// --- Aura's specific Context for Malachite ---
#[derive(Clone, Debug)]
pub struct AuraMalachiteContext;

// Implements the Context trait from `malachitebft_app_channel::app::Context`
impl MalachiteAppChannelContext for AuraMalachiteContext {
    type Address = TestAddress; // Using test address for validators
    type Height = TestHeight; // Using test height
    type ProposalPart = TestProposalPart; // Using test proposal part
    type Proposal = TestProposal; // Using test proposal
    type Validator = TestValidator;
    type ValidatorSet = TestValidatorSet;
    type Value = AuraInternalBlock; // Our application's block is the consensus value
    type Vote = TestVote;
    type Extension = TestExtension;
    type SigningScheme = Ed25519Provider; // Ed25519 for consensus messages

    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        let total_power = validator_set.total_power();
        if total_power == 0 {
            panic!("Cannot select proposer from validator set with zero total power");
        }
        // Simple round-robin based on accumulated power, similar to Tendermint's default.
        // This needs a more robust implementation for production.
        let seed = height.as_u64().wrapping_add(round.as_u32() as u64);
        let mut proposer_index = 0;
        let mut accumulated_power = 0u64;
        for (i, val) in validator_set.validators().iter().enumerate() {
            accumulated_power = accumulated_power.wrapping_add(val.power());
            if accumulated_power >= (seed % total_power) + 1 {
                // Ensure non-zero for modulo
                proposer_index = i;
                break;
            }
        }
        validator_set.validators().get(proposer_index).unwrap()
    }

    fn new_proposal(
        height: Self::Height,
        round: Round,
        value: Self::Value, // This is AuraInternalBlock
        pol_round: Round,
        address: Self::Address, // Proposer's address
    ) -> Self::Proposal {
        // `TestProposal` expects a `TestValue`. We need to map `AuraInternalBlock`'s ID
        // to something `TestValue` can use, or `TestProposal` needs to be generic over `Value::Id`.
        // The `TestValue` is a simple u64. Our `AuraInternalBlock::id()` returns u64 (height).
        warn!(
            "AuraMalachiteContext::new_proposal is using Aura block height as TestValue for TestProposal"
        );
        TestProposal::new(
            height,
            round,
            pol_round,
            TestValue::new(value.id()),
            address,
        )
    }

    fn new_prevote(
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>, // ValueId<Self> is NilOrVal<u64>
        address: Self::Address,
    ) -> Self::Vote {
        TestVote::new_prevote(height, round, value_id, address)
    }

    fn new_precommit(
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote {
        TestVote::new_precommit(height, round, value_id, address)
    }
}

// Our AuraInternalBlock needs to implement MalachiteValueTrait
// It already derives Serialize, Deserialize, Debug, Clone. Add Eq, PartialOrd, Ord.
impl MalachiteValueTrait for AuraInternalBlock {
    type Id = u64; // Block height as ID
    fn id(&self) -> Self::Id {
        self.height
    }
}

// --- AuraNode: Implements MalachiteAppChannelNode trait ---
#[derive(Clone)]
pub struct AuraNode {
    pub home_dir: PathBuf,
    pub aura_app_config: AuraAppNodeConfig, // For app-specific paths like AuraState DB
    pub malachite_config_path: PathBuf,     // Path to malachite_config.toml
    _app_level_private_key: Arc<aura_core::PrivateKey>,
}

pub struct AuraNodeRunningHandle {
    pub app_logic_handle: JoinHandle<()>,
    pub engine_handle: EngineHandle<AuraMalachiteContext>,
    pub tx_event: TxEvent<AuraMalachiteContext>,
}

#[async_trait]
impl MalachiteAppChannelNodeHandle<AuraMalachiteContext> for AuraNodeRunningHandle {
    fn subscribe(&self) -> RxEvent<AuraMalachiteContext> {
        self.tx_event.subscribe()
    }
    async fn kill(&self, _reason: Option<String>) -> eyre::Result<()> {
        self.engine_handle.actor.kill_and_wait(None).await?;
        self.app_logic_handle.abort();
        self.engine_handle.handle.abort();
        Ok(())
    }
}

#[async_trait]
impl MalachiteAppChannelNode for AuraNode {
    type Context = AuraMalachiteContext;
    // This is Malachite's own config struct, NOT your AuraAppNodeConfig
    type Config = MalachiteTopLevelConfig;
    type Genesis = TestGenesis; // Malachite's consensus genesis (validator set)
    // This is the validator's private signing key for consensus messages (Ed25519)
    type PrivateKeyFile = TestPrivateKey;
    type SigningProvider = Ed25519Provider;
    type NodeHandle = AuraNodeRunningHandle;

    fn get_home_dir(&self) -> PathBuf {
        self.home_dir.clone()
    }

    fn load_config(&self) -> eyre::Result<Self::Config> {
        MalachiteTopLevelConfig::load_toml_file(&self.malachite_config_path)
            .map_err(|e| eyre!("Failed to load Malachite config: {}", e))
    }

    fn get_address(&self, pk: &TestPublicKey) -> TestAddress {
        // Takes Malachite's PublicKey type
        TestAddress::from_public_key(pk)
    }

    fn get_public_key(&self, pk: &Self::PrivateKeyFile) -> TestPublicKey {
        // Takes Malachite's PrivateKey type
        pk.public_key()
    }

    fn get_keypair(&self, pk: Self::PrivateKeyFile) -> TestKeypair {
        // Takes Malachite's PrivateKey type
        TestKeypair::ed25519_from_bytes(pk.inner().to_bytes())
            .expect("Failed to create keypair from TestPrivateKey bytes")
    }

    fn load_private_key(&self, file_content: Self::PrivateKeyFile) -> TestPrivateKey {
        file_content
    }

    fn load_private_key_file(&self) -> eyre::Result<Self::PrivateKeyFile> {
        let config = self.load_config()?;
        // Path to priv_validator_key.json should be absolute or resolvable from home_dir
        let key_path = if config.priv_validator_key_file.is_absolute() {
            config.priv_validator_key_file.clone()
        } else {
            self.get_home_dir().join(config.priv_validator_key_file)
        };
        let key_str = fs::read_to_string(&key_path)
            .map_err(|e| eyre!("Failed to read private key file {:?}: {}", key_path, e))?;
        serde_json::from_str(&key_str)
            .map_err(|e| eyre!("Failed to parse private key file {:?}: {}", key_path, e))
    }

    fn get_signing_provider(&self, private_key: Self::PrivateKeyFile) -> Self::SigningProvider {
        Ed25519Provider::new(private_key)
    }

    fn load_genesis(&self) -> eyre::Result<Self::Genesis> {
        let config = self.load_config()?;
        let genesis_path = if config.genesis_file.is_absolute() {
            config.genesis_file.clone()
        } else {
            self.get_home_dir().join(config.genesis_file)
        };
        let genesis_str = fs::read_to_string(&genesis_path)
            .map_err(|e| eyre!("Failed to read genesis file {:?}: {}", genesis_path, e))?;
        serde_json::from_str(&genesis_str)
            .map_err(|e| eyre!("Failed to parse genesis file {:?}: {}", genesis_path, e))
    }

    async fn start(&self) -> eyre::Result<Self::NodeHandle> {
        info!("AuraNode (MalachiteNode impl) starting process...");
        let malachite_config = self.load_config()?;

        let span = tracing::info_span!("aura_node_malachite_instance", moniker = %malachite_config.moniker);
        let _enter = span.enter();

        let priv_validator_key_file_content = self.load_private_key_file()?;
        let priv_validator_key = self.load_private_key(priv_validator_key_file_content);

        let aura_malachite_ctx = AuraMalachiteContext;
        let malachite_genesis = self.load_genesis()?;
        let initial_validator_set = malachite_genesis.validator_set.clone();
        info!(
            "Loaded Malachite consensus genesis with {} validators.",
            initial_validator_set.len()
        );

        let codec = ProtobufCodec;

        // Path for AuraState's DB (application state)
        let app_state_db_path = self.get_home_dir().join(
            &self
                .aura_app_config
                .db_path
                .file_name()
                .expect("App DB path should have a filename"),
        );
        fs::create_dir_all(app_state_db_path.parent().unwrap())?; // Ensure parent dir exists
        let app_state = AuraState::new(app_state_db_path, self._app_level_private_key.clone())?;
        let app_state_arc = Arc::new(Mutex::new(app_state));

        // P2P NodeKey
        let node_key_path = if malachite_config.node_key_file.is_absolute() {
            malachite_config.node_key_file.clone()
        } else {
            self.get_home_dir().join(&malachite_config.node_key_file)
        };
        let node_key_str = fs::read_to_string(&node_key_path).map_err(|e| {
            eyre!(
                "Failed to read P2P node_key file from {:?}: {}",
                node_key_path,
                e
            )
        })?;
        let node_key: NodeKey = serde_json::from_str(&node_key_str) // Assuming NodeKey is Deserialize
            .map_err(|e| {
                eyre!(
                    "Failed to parse P2P node_key file from {:?}: {}",
                    node_key_path,
                    e
                )
            })?;
        info!("Loaded P2P NodeKey: {}", node_key.public_key().to_string());

        info!("Calling malachitebft_app_channel::start_engine...");
        let (mut channels, engine_handle) = malachitebft_app_channel::start_engine(
            aura_malachite_ctx.clone(),
            codec,
            priv_validator_key, // Validator's signing key
            node_key,           // Node's P2P identity key
            malachite_config.clone(),
            None, // Start height (Option<TestHeight>)
            initial_validator_set,
        )
        .await?;
        info!("Malachite engine started via app-channel.");

        let tx_event_channel = channels.events.clone();
        let app_logic_task_span =
            tracing::info_span!("app_message_loop", moniker = %malachite_config.moniker);
        let app_logic_handle = tokio::spawn(
            app_message_loop(app_state_arc, aura_malachite_ctx, channels)
                .instrument(app_logic_task_span),
        );
        info!("Spawned application message loop task.");

        Ok(AuraNodeRunningHandle {
            app_logic_handle,
            engine: engine_handle,
            tx_event: tx_event_channel,
        })
    }

    async fn run(self) -> eyre::Result<()> {
        let handles = self.start().await?;
        handles.app_logic_handle.await.map_err(Into::into)
    }
}

// The application message handling loop
async fn app_message_loop(
    app_state_arc: Arc<Mutex<AuraState>>,
    _ctx: AuraMalachiteContext, // Keep if needed for Ctx methods, else remove
    mut channels: Channels<AuraMalachiteContext>, // `channels` needs to be mutable
) -> eyre::Result<()> {
    info!("Application message loop started. Waiting for messages from consensus...");
    loop {
        tokio::select! {
            Some(msg) = channels.consensus.recv() => {
                debug!("AppLoop: Received AppMsg from consensus: {}", msg_type_name(&msg));
                match msg {
                    AppMsg::ConsensusReady { reply, .. } => {
                        let mut state = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed for ConsensusReady: {}", e))?;
                        // Start from height 1 if current is 0 (genesis), else current_height + 1
                        let start_height = if state.height_value() == 0 {
                            TestHeight::new(1)
                        } else {
                            state.height_value().increment() // Assuming TestHeight implements MalachiteHeightTrait
                        };
                        // TODO: Load actual validator set for start_height from AuraState or TestGenesis
                        let validator_set = TestValidatorSet::new(vec![]);
                        info!(%start_height, "AppLoop: Consensus is ready. Replying with StartHeight.");
                        if reply.send((start_height, validator_set)).is_err() {
                            error!("AppLoop: Failed to send ConsensusReady reply (StartHeight)");
                        }
                    }
                    AppMsg::StartedRound { height, round, proposer, reply_value } => {
                        let mut state_guard = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed for StartedRound: {}", e))?;
                        // Assuming AuraState has methods to update its internal current_height/round
                        // state_guard.set_current_round_info(height, round, proposer);
                        info!(%height, %round, %proposer, "AppLoop: Started round.");
                         if reply_value.send(None).is_err() {
                            error!("AppLoop: Failed to send reply for StartedRound (value reply)");
                         }
                    }
                    AppMsg::GetValue { height, round, reply, .. } => {
                        info!(%height, %round, "AppLoop: Consensus requesting a value (block) to propose.");
                        let mut state_guard = app_state_arc.lock().map_err(|e| eyre!("Mutex lock for GetValue: {}", e))?;

                        // Call AuraState's begin_block to prepare for new block proposal internally if needed
                        // This might not be needed if GetValue is purely about fetching/creating the value
                        // For now, AuraState.begin_block is called by AppMsg::Decided's StartHeight path

                        let new_aura_block = AuraInternalBlock {
                            height: height.as_u64(),
                            proposer_address: "aura_node_self_proposing".to_string(), // Placeholder
                            timestamp: chrono::Utc::now().timestamp(),
                            transactions: vec![],
                        };

                        let locally_proposed_value = LocallyProposedValue {
                            height,
                            round,
                            value: new_aura_block.clone(), // Clone here
                        };

                        if reply.send(locally_proposed_value).is_err() {
                            error!("AppLoop: Failed to send GetValue reply (LocallyProposedValue)");
                        }

                        // Stream the proposal parts
                        // This requires AuraInternalBlock to be splittable into Ctx::ProposalPart (TestProposalPart)
                        // For TestProposalPart, it might be simple (e.g. if it's just bytes)
                        warn!("AppLoop: TODO: Implement streaming of AuraInternalBlock as TestProposalParts for GetValue");
                        // Example structure (conceptual):
                        // let stream_id = ctx.new_stream_id(height, round); // Ctx needs new_stream_id or similar
                        // let parts: Vec<TestProposalPart> = split_aura_block_into_test_parts(&new_aura_block);
                        // for (seq, part_content) in parts.into_iter().enumerate() {
                        //    let stream_msg = StreamMessage::new(stream_id.clone(), seq as u64, StreamContent::Data(part_content));
                        //    if channels.network.send(NetworkMsg::PublishProposalPart(stream_msg)).await.is_err() {
                        //        error!("AppLoop: Failed to send proposal part to network");
                        //    }
                        // }
                        // let fin_msg = StreamMessage::new(stream_id, parts.len() as u64, StreamContent::Fin);
                        // if channels.network.send(NetworkMsg::PublishProposalPart(fin_msg)).await.is_err() { ... }

                    }
                    AppMsg::ReceivedProposalPart { from, part, reply } => {
                        let part_type_str = match &part.content {
                            StreamContent::Data(p) => format!("{:?}", p),
                            StreamContent::Fin => "Fin".to_string(),
                        };
                        info!(peer_id = %from, sequence = %part.sequence, part_type = %part_type_str, "AppLoop: Received proposal part.");
                        // TODO: Implement logic in AuraState or here to accumulate parts using a structure like PartStreamsMap.
                        // When full block (AuraInternalBlock) is reassembled:
                        // let reassembled_block: AuraInternalBlock = ...;
                        // let proposed_value = ProposedValue {
                        //    height: part.stream_id_height(), // Assuming stream_id contains H/R
                        //    round: part.stream_id_round(),
                        //    valid_round: Round::Nil, // Or from Init part
                        //    proposer: from_address, // Need to map PeerId to Ctx::Address
                        //    value: reassembled_block,
                        //    validity: Validity::Pending, // Or Valid if signature verified
                        // };
                        // if reply.send(Some(proposed_value)).is_err() { ... }
                        // else if reply.send(None).is_err() { ... }
                        if reply.send(None).is_err() {
                             error!("AppLoop: Failed to send ReceivedProposalPart reply");
                        }
                    }
                    AppMsg::Decided { certificate, extensions: _, reply } => {
                        info!(height = %certificate.height, round = %certificate.round, value_id = %certificate.value_id, "AppLoop: Consensus decided. Committing block.");
                        let mut state_guard = app_state_arc.lock().map_err(|e| eyre!("Mutex lock for Decided: {}", e))?;

                        // Assuming certificate.value_id (which is ValueId<C> where C::Value::Id = u64)
                        // matches the height of the block to be committed.
                        // AuraState::commit_block internally uses its `pending_block_...` fields.
                        // We need to ensure these were set correctly by a preceding `GetValue` (if proposer)
                        // or by reconstructed block from `ReceivedProposalPart` (if verifier).
                        // This part of the state flow needs careful review.
                        // The tutorial's `State::commit` fetches the proposal from its store using value_id.

                        // Simplified: Assume the block to commit is what was last processed/staged by `begin_block` and `deliver_tx`
                        // This implies that before `Decided` is received, the app should have processed the block's contents
                        // via `BeginBlock` (from Malachite consensus) and `DeliverTx` (if txs were in the block).
                        // The tutorial's `State` seems to store the `ProposedValue` in its `store_undecided_proposal`.
                        // Then `commit` fetches it.

                        // For Aura, the sequence might be:
                        // 1. Malachite calls App: BeginBlock(H) -> AuraState.begin_block(H, proposer, time)
                        // 2. Malachite calls App: DeliverTx(tx1), DeliverTx(tx2) -> AuraState.deliver_tx(tx) for each
                        // 3. Malachite calls App: EndBlock(H) -> AuraState.end_block(H)
                        // 4. Malachite calls App: Commit() -> AuraState.commit_block() // This commits the staged block
                        // So, when Decided arrives, the block for certificate.height should have already been
                        // processed and is ready to be finalized by AuraState.commit_block().
                        // The `certificate.value_id` should match `state_guard.pending_block_height` (as u64).

                        if certificate.value_id.val_or_nil().map_or(true, |id_val| id_val != state_guard.pending_block_height) {
                             error!("AppLoop: Decided value_id {} does not match pending block height {}. Inconsistency!",
                                certificate.value_id, state_guard.pending_block_height);
                             // Handle error, perhaps request restart for current height.
                        }

                        match state_guard.commit_block() { // commit_block uses pending_block_height
                            Ok(_app_hash) => {
                                let next_height = state_guard.height_value().increment(); // Get new current height and increment
                                let validator_set = TestValidatorSet::new(vec![]); // Placeholder
                                info!("AppLoop: Commit successful. Replying to start next height: {}", next_height);
                                if reply.send(ConsensusMsg::StartHeight(next_height, validator_set)).is_err() {
                                    error!("AppLoop: Failed to send Decided reply (StartHeight)");
                                }
                            }
                            Err(e) => {
                                error!("AppLoop: Commit failed after Decided: {:?}. Requesting restart for height {}.", e, state_guard.pending_block_height);
                                let current_pending_height = TestHeight::new(state_guard.pending_block_height); // Height to restart
                                let validator_set = TestValidatorSet::new(vec![]); // Placeholder
                                if reply.send(ConsensusMsg::RestartHeight(current_pending_height, validator_set)).is_err() {
                                     error!("AppLoop: Failed to send Decided reply (RestartHeight)");
                                }
                            }
                        }
                    }
                    AppMsg::ExtendVote { reply, .. } => {
                        if reply.send(None).is_err() { error!("AppLoop: Failed to send ExtendVote reply"); }
                    }
                    AppMsg::VerifyVoteExtension { reply, .. } => {
                        if reply.send(Ok(())).is_err() { error!("AppLoop: Failed to send VerifyVoteExtension reply");}
                    }
                    AppMsg::GetValidatorSet { height, reply } => {
                        info!("AppLoop: GetValidatorSet called for height {}", height);
                        // TODO: Implement actual validator set retrieval from AuraState based on height
                        let vs_placeholder = TestValidatorSet::new(vec![]);
                        if reply.send(vs_placeholder).is_err() {
                            error!("AppLoop: Failed to send GetValidatorSet reply");
                        }
                    }
                    AppMsg::GetHistoryMinHeight { reply } => {
                         info!("AppLoop: GetHistoryMinHeight called");
                        // TODO: Implement actual min height retrieval from AuraState
                        let min_h_placeholder = TestHeight::new(0);
                        if reply.send(min_h_placeholder).is_err() {
                             error!("AppLoop: Failed to send GetHistoryMinHeight reply");
                        }
                    }
                     AppMsg::GetDecidedValue { height, reply } => {
                        info!("AppLoop: GetDecidedValue called for height {}", height);
                        // TODO: Implement retrieval of decided AuraInternalBlock from AuraState
                        // and convert to malachite_app_channel::app::types::RawDecidedValue
                        if reply.send(None).is_err() {
                            error!("AppLoop: Failed to send GetDecidedValue reply");
                        }
                    }
                    AppMsg::ProcessSyncedValue { height, round, proposer, value_bytes, reply } => {
                        info!(%height, %round, "AppLoop: Processing synced value ({} bytes)", value_bytes.len());
                        // TODO: Decode value_bytes into AuraInternalBlock (Ctx::Value) using ProtobufCodec (or your codec)
                        // Then create ProposedValue and send Some(proposed_value) in reply.
                        // If decode fails, send None.
                        if reply.send(None).is_err() {
                           error!("AppLoop: Failed to send ProcessSyncedValue reply");
                        }
                    }
                    AppMsg::PeerJoined { peer_id } => { info!(%peer_id, "AppLoop: Peer joined."); }
                    AppMsg::PeerLeft { peer_id } => { info!(%peer_id, "AppLoop: Peer left.");}
                    _ => { warn!("AppLoop: Unhandled AppMsg variant: {}", msg_type_name(&msg));}
                }
            }
            else => {
                info!("AppLoop: Consensus channel closed or select! macro completed. Exiting loop.");
                break;
            }
        }
    }
    Ok(())
}

// Helper to get a string name for AppMsg variants for logging
fn msg_type_name<C: MalachiteContext>(msg: &AppMsg<C>) -> &'static str {
    match msg {
        AppMsg::ConsensusReady { .. } => "ConsensusReady",
        AppMsg::StartedRound { .. } => "StartedRound",
        AppMsg::GetValue { .. } => "GetValue",
        AppMsg::ExtendVote { .. } => "ExtendVote",
        AppMsg::VerifyVoteExtension { .. } => "VerifyVoteExtension",
        AppMsg::RestreamProposal { .. } => "RestreamProposal",
        AppMsg::GetHistoryMinHeight { .. } => "GetHistoryMinHeight",
        AppMsg::ReceivedProposalPart { .. } => "ReceivedProposalPart",
        AppMsg::GetValidatorSet { .. } => "GetValidatorSet",
        AppMsg::Decided { .. } => "Decided",
        AppMsg::GetDecidedValue { .. } => "GetDecidedValue",
        AppMsg::ProcessSyncedValue { .. } => "ProcessSyncedValue",
        AppMsg::PeerJoined { .. } => "PeerJoined",
        AppMsg::PeerLeft { .. } => "PeerLeft",
        #[allow(unreachable_patterns)]
        _ => "UnknownAppMsg",
    }
}
