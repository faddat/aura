use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc; // For channels if we need to create them for app internal comms
use tokio::task::JoinHandle;

use async_trait::async_trait;
use tracing::{Instrument, debug, error, info, warn}; // Added Instrument

use crate::Error as AuraError;
use crate::Result as AuraLibResult;
use crate::config::AuraNodeConfig as AuraAppNodeConfig;
use crate::state::{
    AuraState, Block as AuraInternalBlock, ExecTxResult, ValidatorUpdate as AuraValidatorUpdate,
};

// --- Malachite App Channel Imports ---
use malachitebft_app_channel::{
    AppMsg, // Messages received by App from Consensus/Network
    Channels,
    EngineHandle,
    RxEvent, // For subscribing to engine events
    TxEvent,
    app::{
        ConsensusMsg, // Messages sent from App to Consensus
        Context as MalachiteContext,
        NetworkMsg,                        // Messages sent from App to Network
        Node as MalachiteNode,             // The trait AuraNode will implement
        NodeHandle as MalachiteNodeHandle, // Trait for the handle returned by start()
        types::{
            NilOrVal,
            Round,
            SignedConsensusMsg, // For Codec
            ValueId,
            // Core types traits
            core::{
                Address as MalachiteAddressTrait, Extension as MalachiteExtensionTrait,
                Height as MalachiteHeightTrait, Proposal as MalachiteProposalTrait,
                ProposalPart as MalachiteProposalPartTrait,
                SigningScheme as MalachiteSigningSchemeTrait, Validator as MalachiteValidatorTrait,
                ValidatorSet as MalachiteValidatorSetTrait, Value as MalachiteValueTrait,
                Vote as MalachiteVoteTrait,
            },
            streaming::StreamMessage, // For Codec
            sync::{
                Request as MalachiteSyncRequest, Response as MalachiteSyncResponse,
                Status as MalachiteSyncStatus,
            }, // For Codec
        },
    },
};

// --- Malachite Config ---
// Using the Malachite config types directly from the provided source
use malachitebft_config::{
    ConsensusConfig as MalachiteBftConsensusConfig,
    P2pConfig as MalachiteBftP2pConfig,
    // Assuming a top-level config like the tutorial's `Config`
    // This is a placeholder, you need to define/find Malachite's actual top-level config struct
    // that incorporates P2pConfig, ConsensusConfig, paths to keys, genesis, etc.
};
// Placeholder for Malachite's top-level config, similar to tutorial's `Config`
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MalachiteTopLevelConfig {
    pub moniker: String,
    pub home: PathBuf, // Base directory for keys, db, etc.
    // Paths relative to 'home' or absolute
    pub genesis_file: PathBuf,
    pub priv_validator_key_file: PathBuf,
    // pub node_key_file: PathBuf, // NodeKey for P2P might be separate or part of priv_validator_key
    pub p2p: MalachiteBftP2pConfig,
    pub consensus: MalachiteBftConsensusConfig,
    // Add other necessary fields like mempool, rpc, logging, etc.
    // pub logging: LoggingConfig,
}
impl MalachiteTopLevelConfig {
    pub fn load_toml_file<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let config_str = fs::read_to_string(path.as_ref())?;
        toml::from_str(&config_str).map_err(anyhow::Error::from)
    }
}

// --- Malachite Core Types & Test Types ---
// For simplicity, using types from malachitebft-test as the tutorial suggests.
// You'll need to ensure these dependencies are in aura-node-lib/Cargo.toml
// and potentially rename them (e.g., `malachitebft_test_types = { package = "informalsystems-malachitebft-test", ... }`)
use malachitebft_core_types::NodeKey;
use malachitebft_test::{
    Address as TestAddress,     // Implements MalachiteAddressTrait
    Context as TestContext,     // Implements MalachiteContext
    Ed25519Provider,            // Implements SigningScheme
    Extension as TestExtension, // Implements MalachiteExtensionTrait
    Genesis as TestGenesis,     // Contains initial validator set
    Height as TestHeight,       // Implements MalachiteHeightTrait
    Keypair as TestKeypair,
    PrivateKey as TestPrivateKey,     // Validator signing key
    Proposal as TestProposal,         // Implements MalachiteProposalTrait
    ProposalPart as TestProposalPart, // Implements MalachiteProposalPartTrait
    PublicKey as TestPublicKey,
    Validator as TestValidator,       // Implements MalachiteValidatorTrait
    ValidatorSet as TestValidatorSet, // Implements MalachiteValidatorSetTrait
    Value as TestValue, // Implements MalachiteValueTrait - OURS WILL BE AuraInternalBlock
    Vote as TestVote,   // Implements MalachiteVoteTrait
    codec::proto::ProtobufCodec, // Implements Codec
}; // This is distinct, for P2P identity.

// --- Aura's specific Value type for consensus (our Block) ---
// It needs to implement `MalachiteValueTrait`.
// For now, AuraInternalBlock is fine. We'll need to implement MalachiteValueTrait for it.
// type AuraConsensusValue = AuraInternalBlock; // This will be `Ctx::Value`

// --- Aura's specific Context for Malachite ---
// This struct will implement `malachitebft_app_channel::app::types::core::Context`
#[derive(Clone, Debug)]
pub struct AuraMalachiteContext; // Needs to be a unit struct or have fields

// TODO: Implement `MalachiteContext` for `AuraMalachiteContext`
// This involves defining associated types (Height, Address, Value, etc.)
// and implementing methods like `select_proposer`, `new_proposal`, etc.
// For many types, we can reuse `malachitebft_test` types initially.
// Crucially, `type Value = AuraInternalBlock;`
// and `AuraInternalBlock` must implement `MalachiteValueTrait`.

impl MalachiteContext for AuraMalachiteContext {
    type Address = TestAddress;
    type Height = TestHeight; // Using test height for now
    type ProposalPart = TestProposalPart; // Placeholder, needs to be parts of AuraInternalBlock
    type Proposal = TestProposal; // Placeholder, needs to be AuraInternalBlock + header info
    type Validator = TestValidator;
    type ValidatorSet = TestValidatorSet;
    type Value = AuraInternalBlock; // Our Block type!
    type Vote = TestVote;
    type Extension = TestExtension; // Or a custom Aura extension type
    type SigningScheme = Ed25519Provider; // Malachite uses Ed25519 for consensus messages

    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        // Simple round-robin proposer selection for now, adapt as needed
        let index = (height.as_u64() + round.as_u32() as u64) as usize % validator_set.len();
        validator_set
            .validators()
            .get(index)
            .expect("Validator set should not be empty")
    }

    // This creates Malachite's Proposal type, which wraps our Value (AuraInternalBlock)
    fn new_proposal(
        height: Self::Height,
        round: Round,
        value: Self::Value, // This is AuraInternalBlock
        pol_round: Round,
        address: Self::Address,
    ) -> Self::Proposal {
        // TestProposal::new expects TestValue. We need to adapt.
        // This is a major point of integration.
        // For now, let's create a dummy TestProposal if TestValue can be made from AuraInternalBlock id
        // This requires AuraInternalBlock to have an id() method usable for TestValue::id()
        warn!("AuraMalachiteContext::new_proposal is using a placeholder implementation!");
        let dummy_test_value_id = value.height as u64; // Highly simplified
        TestProposal::new(
            height,
            round,
            pol_round,
            TestValue::new(dummy_test_value_id),
            address,
        )
    }

    fn new_prevote(
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
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
impl MalachiteValueTrait for AuraInternalBlock {
    type Id = u64; // Using block height as a simple ID for now. A hash would be better.

    fn id(&self) -> Self::Id {
        self.height // Or a hash of the block
    }
}

// --- AuraNode: Implements MalachiteNode trait ---
#[derive(Clone)] // MalachiteNode requires Clone
pub struct AuraNode {
    // Fields from the tutorial's App struct
    pub home_dir: PathBuf, // Base data directory for this node instance
    pub aura_app_config: AuraAppNodeConfig, // Your existing app-level config for paths etc.
    pub malachite_config_path: PathBuf, // Path to malachite's own config.toml

    // Store app_level_private_key if needed for app logic, not directly by MalachiteNode trait
    _app_level_private_key: Arc<aura_core::PrivateKey>,
}

// This struct will hold the handles to the running components
pub struct AuraNodeRunningHandle {
    pub app_logic_handle: JoinHandle<()>, // Handle to the task running our app_message_loop
    pub engine_handle: EngineHandle<AuraMalachiteContext>, // Handle to Malachite's engine
    pub tx_event: TxEvent<AuraMalachiteContext>, // For subscribing to events
}

#[async_trait]
impl MalachiteNodeHandle<AuraMalachiteContext> for AuraNodeRunningHandle {
    fn subscribe(&self) -> RxEvent<AuraMalachiteContext> {
        self.tx_event.subscribe()
    }

    async fn kill(&self, _reason: Option<String>) -> eyre::Result<()> {
        // Gracefully shut down components
        self.engine_handle.actor.kill_and_wait(None).await?; // Kill consensus engine actor
        self.app_logic_handle.abort(); // Abort the application logic task
        self.engine_handle.handle.abort(); // Abort the engine's main task handle
        Ok(())
    }
}

#[async_trait]
impl MalachiteNode for AuraNode {
    type Context = AuraMalachiteContext;
    type Config = MalachiteTopLevelConfig; // Malachite's top-level config
    type Genesis = TestGenesis; // Malachite's genesis (validator set)
    type PrivateKeyFile = TestPrivateKey; // Malachite's validator signing key
    type SigningProvider = Ed25519Provider; // For signing consensus messages
    type NodeHandle = AuraNodeRunningHandle; // Our custom handle

    fn get_home_dir(&self) -> PathBuf {
        self.home_dir.clone()
    }

    fn load_config(&self) -> eyre::Result<Self::Config> {
        MalachiteTopLevelConfig::load_toml_file(&self.malachite_config_path)
            .map_err(|e| eyre::eyre!("Failed to load Malachite config: {}", e))
    }

    // --- Key Management (for Malachite's consensus keys) ---
    fn get_address(&self, pk: &TestPublicKey) -> TestAddress {
        TestAddress::from_public_key(pk)
    }

    fn get_public_key(&self, pk: &Self::PrivateKeyFile) -> TestPublicKey {
        pk.public_key()
    }

    fn get_keypair(&self, pk: Self::PrivateKeyFile) -> TestKeypair {
        TestKeypair::ed25519_from_bytes(pk.inner().to_bytes())
            .expect("Failed to create keypair from TestPrivateKey bytes")
    }

    fn load_private_key(&self, file_content: Self::PrivateKeyFile) -> TestPrivateKey {
        file_content // Assuming PrivateKeyFile is the key itself
    }

    fn load_private_key_file(&self) -> eyre::Result<Self::PrivateKeyFile> {
        // Malachite's config should point to priv_validator_key.json
        let config = self.load_config()?;
        let key_path = self.get_home_dir().join(config.priv_validator_key_file); // Path from config
        let key_str = fs::read_to_string(&key_path)
            .map_err(|e| eyre::eyre!("Failed to read private key file {:?}: {}", key_path, e))?;
        serde_json::from_str(&key_str)
            .map_err(|e| eyre::eyre!("Failed to parse private key file {:?}: {}", key_path, e))
    }

    fn get_signing_provider(&self, private_key: Self::PrivateKeyFile) -> Self::SigningProvider {
        Ed25519Provider::new(private_key)
    }

    fn load_genesis(&self) -> eyre::Result<Self::Genesis> {
        let config = self.load_config()?;
        let genesis_path = self.get_home_dir().join(config.genesis_file); // Path from config
        let genesis_str = fs::read_to_string(&genesis_path)
            .map_err(|e| eyre::eyre!("Failed to read genesis file {:?}: {}", genesis_path, e))?;
        serde_json::from_str(&genesis_str)
            .map_err(|e| eyre::eyre!("Failed to parse genesis file {:?}: {}", genesis_path, e))
    }

    async fn start(&self) -> eyre::Result<Self::NodeHandle> {
        info!("AuraNode (MalachiteNode impl) starting...");
        let malachite_config = self.load_config()?; // Malachite's top-level config

        let span = tracing::info_span!("aura_node", moniker = %malachite_config.moniker);
        let _enter = span.enter();

        // Load Malachite's private validator key for signing consensus messages
        let priv_validator_key_file = self.load_private_key_file()?;
        let priv_validator_key = self.load_private_key(priv_validator_key_file);
        let _public_key = self.get_public_key(&priv_validator_key); // For logging or validator set creation
        let _address = self.get_address(&_public_key); // This node's consensus address

        // Signing provider for consensus messages
        let signing_provider = self.get_signing_provider(priv_validator_key.clone()); // Clone if needed by engine later

        // Aura's context for Malachite
        let aura_malachite_ctx = AuraMalachiteContext;

        // Load Malachite's genesis (initial validator set)
        let malachite_genesis = self.load_genesis()?;
        let initial_validator_set = malachite_genesis.validator_set.clone();
        info!(
            "Loaded Malachite genesis with {} validators.",
            initial_validator_set.len()
        );

        // Codec for network messages
        let codec = ProtobufCodec; // As used in the tutorial

        // Initialize AuraState (application state)
        // Path for AuraState's DB comes from AuraAppNodeConfig
        let aura_state_db_path = self.home_dir.join(&self.aura_app_config.db_path); // Ensure db_path is relative or handled
        let app_state = AuraState::new(aura_state_db_path, self._app_level_private_key.clone())?;
        let app_state_arc = Arc::new(Mutex::new(app_state));

        // NodeKey for P2P (distinct from validator signing key)
        // Path for NodeKey might be in malachite_config or a convention
        // For now, assume it's `node_key.json` in `home_dir`.
        let node_key_path = self.get_home_dir().join("node_key.json");
        let node_key_str = fs::read_to_string(&node_key_path).map_err(|e| {
            eyre::eyre!(
                "Failed to read node_key.json from {:?}: {}",
                node_key_path,
                e
            )
        })?;
        let node_key: NodeKey = serde_json::from_str(&node_key_str).map_err(|e| {
            eyre::eyre!(
                "Failed to parse node_key.json from {:?}: {}",
                node_key_path,
                e
            )
        })?;
        info!("Loaded P2P NodeKey: {}", node_key.public_key().to_string());

        // Start Malachite Engine using malachitebft_app_channel::start_engine
        info!("Calling malachitebft_app_channel::start_engine...");
        let (mut channels, engine_handle) = malachitebft_app_channel::start_engine(
            aura_malachite_ctx.clone(), // Our context
            codec,                      // Protobuf codec
            priv_validator_key,         // The validator's signing key
            node_key,                   // The node's P2P identity key
            malachite_config.clone(),   // Malachite's top-level config
            None, // Start height (Option<Self::Context::Height>), None means from genesis/WAL
            initial_validator_set, // From Malachite's genesis
        )
        .await?;
        info!("Malachite engine started via app-channel.");

        let tx_event_channel = channels.events.clone();

        // Spawn the application logic loop to handle messages from Malachite
        let app_logic_task_span =
            tracing::info_span!("app_message_loop", moniker = %malachite_config.moniker);
        let app_logic_handle = tokio::spawn(
            async move {
                if let Err(e) =
                    app_message_loop(app_state_arc, aura_malachite_ctx, &mut channels).await
                {
                    error!("Application message loop error: {:?}", e);
                }
            }
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
        // Wait for the application logic task to complete (it might run indefinitely)
        // Or just let main exit if node start is meant to be non-blocking at this level.
        // The tutorial's `app.run()` waits on `app_handle.await`.
        handles.app_logic_handle.await.map_err(Into::into)
    }
}

// The application message handling loop (analogous to `app::run` in the tutorial)
async fn app_message_loop(
    app_state_arc: Arc<Mutex<AuraState>>,
    ctx: AuraMalachiteContext, // Pass context for creating proposals/votes if needed
    channels: &mut Channels<AuraMalachiteContext>,
) -> eyre::Result<()> {
    info!("Application message loop started. Waiting for messages from consensus...");
    loop {
        tokio::select! {
            Some(msg) = channels.consensus.recv() => {
                debug!("Received AppMsg from consensus: {:?}", msg_type_name(&msg));
                match msg {
                    AppMsg::ConsensusReady { reply, .. } => {
                        let mut state = app_state_arc.lock().expect("Failed to lock app state for ConsensusReady");
                        let start_height = state.height_value().increment_by(1); // Start at current_height + 1
                        let validator_set = TestValidatorSet::new(vec![]); // Placeholder, load from state or genesis
                        info!(%start_height, "Consensus is ready. Replying with StartHeight.");
                        if reply.send((start_height, validator_set.clone())).is_err() {
                            error!("Failed to send ConsensusReady reply (StartHeight)");
                        }
                    }
                    AppMsg::StartedRound { height, round, proposer, reply_value } => {
                        let mut state = app_state_arc.lock().expect("Failed to lock app state for StartedRound");
                        state.current_height = height; // Assuming TestHeight can be converted or stored
                        state.current_round = round;
                        // state.current_proposer = Some(proposer); // Proposer type mismatch
                        info!(%height, %round, %proposer, "App: Started round.");
                        // Tutorial re-sends existing proposal if any. For Aura, this means checking AuraState.
                        // If reply_value.send(Some(existing_aura_block_as_malachite_proposal)).is_err() ...
                         if reply_value.send(None).is_err() { // Send None if no pre-existing proposal for this H/R
                            error!("Failed to send reply for StartedRound (value reply)");
                         }
                    }
                    AppMsg::GetValue { height, round, timeout: _, reply } => {
                        info!(%height, %round, "App: Consensus requesting a value (block) to propose.");
                        let mut state = app_state_arc.lock().expect("Failed to lock app state for GetValue");

                        // Construct an AuraInternalBlock
                        // In a real scenario, pull transactions from mempool via AuraState
                        let new_aura_block = AuraInternalBlock {
                            height: height.as_u64(), // Convert from TestHeight
                            proposer_address: "aura_proposer_placeholder".to_string(), // Get actual proposer from context if needed
                            timestamp: chrono::Utc::now().timestamp(),
                            transactions: vec![], // TODO: Populate with transactions
                        };

                        // This `LocallyProposedValue` is specific to `malachitebft-test` context.
                        // We need to construct what Malachite expects for `Ctx::Value`.
                        // `AuraMalachiteContext::Value` is `AuraInternalBlock`.
                        // The reply channel expects `LocallyProposedValue<AuraMalachiteContext>`
                        // which implies `malachitebft_app_channel::app::types::LocallyProposedValue`
                        // This type takes Ctx::Value, so it expects AuraInternalBlock.

                        // For now, we directly send our AuraInternalBlock as Ctx::Value.
                        // The `LocallyProposedValue` wrapper might be from the tutorial's specific setup.
                        // The `AppMsg::GetValue` reply channel is `Sender<LocallyProposedValue<C>>`
                        // where `LocallyProposedValue<C>` has `height: C::Height, round: Round, value: C::Value`.
                        let locally_proposed_value = malachitebft_app_channel::app::types::LocallyProposedValue {
                            height, // C::Height
                            round,  // Round
                            value: new_aura_block, // C::Value
                        };

                        if reply.send(locally_proposed_value).is_err() {
                            error!("Failed to send GetValue reply (LocallyProposedValue)");
                        }
                        // TODO: Application should then stream this block out as parts via NetworkMsg::PublishProposalPart
                        // This involves splitting `new_aura_block` into `Ctx::ProposalPart`s.
                    }
                    AppMsg::ReceivedProposalPart { from, part, reply } => {
                        let part_type_str = match &part.content {
                            malachitebft_app_channel::app::types::streaming::StreamContent::Data(p) => format!("{:?}", p), // Adjust based on TestProposalPart
                            malachitebft_app_channel::app::types::streaming::StreamContent::Fin => "Fin".to_string(),
                        };
                        info!(peer_id = %from, sequence = %part.sequence, part_type = %part_type_str, "App: Received proposal part.");
                        // TODO: Implement logic to collect parts and reconstruct an AuraInternalBlock
                        // let mut state = app_state_arc.lock().expect("State lock for ReceivedProposalPart");
                        // let full_block_opt = state.handle_received_proposal_part(from, part)?;
                        // The reply is `Sender<Option<ProposedValue<C>>>`
                        // `ProposedValue<C>` has `height, round, valid_round, proposer, value: C::Value, validity`.
                        if reply.send(None).is_err() { // Send None if block not yet complete
                             error!("Failed to send ReceivedProposalPart reply");
                        }
                    }
                    AppMsg::Decided { certificate, extensions: _, reply } => {
                        info!(height = %certificate.height, round = %certificate.round, value_id = %certificate.value_id, "App: Consensus decided. Committing block.");
                        let mut state = app_state_arc.lock().expect("State lock for Decided");
                        // `certificate.value_id` is `ValueId<C>`. Our `C::Value::Id` is u64 (block height).
                        // We need to fetch the actual block from `AuraState`'s pending/staged data,
                        // as the certificate only has the ID.
                        // The `AuraState::commit_block` method needs to be adapted to this.
                        // It currently assumes it has the full block internally.
                        // For now, let's assume commit_block uses its internally staged block.
                        match state.commit_block() {
                            Ok(_app_hash) => {
                                let next_height = state.height_value().increment_by(1);
                                let validator_set = TestValidatorSet::new(vec![]); // Placeholder
                                if reply.send(ConsensusMsg::StartHeight(next_height, validator_set)).is_err() {
                                    error!("Failed to send Decided reply (StartHeight)");
                                }
                            }
                            Err(e) => {
                                error!("App: Commit failed after Decided: {:?}. Requesting restart.", e);
                                let current_height = state.height_value(); // Height to restart
                                let validator_set = TestValidatorSet::new(vec![]); // Placeholder
                                if reply.send(ConsensusMsg::RestartHeight(current_height, validator_set)).is_err() {
                                     error!("Failed to send Decided reply (RestartHeight)");
                                }
                            }
                        }
                    }
                    // --- Implement other AppMsg handlers based on the tutorial ---
                    AppMsg::ExtendVote { height: _, round: _, value_id: _, reply } => {
                        if reply.send(None).is_err() { // No extension for now
                            error!("Failed to send ExtendVote reply");
                        }
                    }
                    AppMsg::VerifyVoteExtension { height: _, round: _, value_id: _, extension: _, reply } => {
                        if reply.send(Ok(())).is_err() { // Always valid for now
                             error!("Failed to send VerifyVoteExtension reply");
                        }
                    }
                    AppMsg::GetValidatorSet { height, reply } => {
                        // let state = app_state_arc.lock().expect("State lock for GetValidatorSet");
                        // let vs = state.get_validator_set_for_malachite(height); // You'd need this method
                        let vs_placeholder = TestValidatorSet::new(vec![]); // Placeholder
                        if reply.send(vs_placeholder).is_err() {
                            error!("Failed to send GetValidatorSet reply");
                        }
                    }
                    AppMsg::GetHistoryMinHeight { reply } => {
                        // let state = app_state_arc.lock().expect("State lock for GetHistoryMinHeight");
                        // let min_h = state.get_earliest_height_for_malachite(); // You'd need this method
                        let min_h_placeholder = TestHeight::new(0); // Placeholder
                        if reply.send(min_h_placeholder).is_err() {
                             error!("Failed to send GetHistoryMinHeight reply");
                        }
                    }
                     AppMsg::GetDecidedValue { height, reply } => {
                        // let state = app_state_arc.lock().expect("State lock for GetDecidedValue");
                        // let decided_value_opt = state.get_decided_aura_block(height);
                        // Convert AuraInternalBlock to RawDecidedValue if found
                        if reply.send(None).is_err() { // Placeholder: value not found
                            error!("Failed to send GetDecidedValue reply");
                        }
                    }
                    AppMsg::ProcessSyncedValue { height, round, proposer, value_bytes, reply } => {
                        info!(%height, %round, "App: Processing synced value ({} bytes)", value_bytes.len());
                        // TODO: Decode value_bytes into AuraInternalBlock using your chosen Codec for Ctx::Value
                        // let aura_block_result = YourCodec::decode::<AuraInternalBlock>(value_bytes);
                        // if let Ok(aura_block) = aura_block_result {
                        //    let proposed_value = ProposedValue { height, round, valid_round: Round::Nil, proposer, value: aura_block, validity: Validity::Valid };
                        //    state.store_undecided_proposal(proposed_value.clone()).await?; // If AuraState has such a method
                        //    if reply.send(proposed_value).is_err() { error!("...") }
                        // } else {
                        //    if reply.send(None).is_err() { error!("...") }
                        // }
                        if reply.send(None).is_err() { // Placeholder: decode failed or not implemented
                           error!("Failed to send ProcessSyncedValue reply");
                        }
                    }
                    AppMsg::PeerJoined { peer_id } => {
                        info!(%peer_id, "App: Peer joined.");
                        // let mut state = app_state_arc.lock().expect("State lock for PeerJoined");
                        // state.add_peer(peer_id);
                    }
                    AppMsg::PeerLeft { peer_id } => {
                         info!(%peer_id, "App: Peer left.");
                        // let mut state = app_state_arc.lock().expect("State lock for PeerLeft");
                        // state.remove_peer(peer_id);
                    }
                    // Add other message handlers as needed
                    _ => {
                        warn!("Unhandled AppMsg variant: {:?}", msg_type_name(&msg));
                    }
                }
            }
            // Handle other events or shutdown signals if necessary
            else => {
                info!("App message loop: Consensus channel closed or no message. Exiting loop.");
                break;
            }
        }
    }
    Ok(())
}

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
        // Add any other variants from your Malachite version's AppMsg
        #[allow(unreachable_patterns)] // In case some variants are not public or covered by _
        _ => "UnknownAppMsg",
    }
}
