use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex}; // Corrected Mutex import

use async_trait::async_trait;
use eyre::eyre;
use tracing::{Instrument, debug, error, info, warn};

use crate::config::AuraNodeConfig as AuraAppNodeConfig;
use crate::state::{AuraState, Block as AuraInternalBlock, ValidatorUpdate as AuraValidatorUpdate};
// Note: AuraLibResult and AuraError are implicitly available via `crate::*`

// --- Malachite App Channel Imports ---
// These types are central when using the app-channel.
use malachitebft_app_channel::{
    AppMsg,
    Channels,
    EngineHandle,
    RxEvent,
    TxEvent,
    app::{
        // Types re-exported by app-channel from malachitebft-app and core-types
        ConsensusMsg,
        Context as MalachiteAppChannelContext, // The Context trait we implement for channel-based apps
        NetworkMsg,
        Node as MalachiteAppChannelNode,
        NodeHandle as MalachiteAppChannelNodeHandle,
        types::{
            LocallyProposedValue,
            NilOrVal,
            ProposedValue,
            Round,
            ValueId,
            // We might not need these sync types directly here if `start_engine` handles them
            // sync::{Status as MalachiteSyncStatus, Request as MalachiteSyncRequest, Response as MalachiteSyncResponse},
            core::{
                // Core traits for our context's associated types
                Address as MalachiteAddressTrait,
                Extension as MalachiteExtensionTrait,
                Height as MalachiteHeightTrait,
                Proposal as MalachiteProposalTrait,
                ProposalPart as MalachiteProposalPartTrait,
                SigningScheme as MalachiteSigningSchemeTrait,
                Validator as MalachiteValidatorTrait,
                ValidatorSet as MalachiteValidatorSetTrait,
                Value as MalachiteValueTrait,
                Vote as MalachiteVoteTrait,
            },
        },
    },
    start_engine as malachite_start_engine, // Import start_engine
};

// --- Malachite Config ---
use malachitebft_config::{
    ConsensusConfig as MalachiteBftConsensusConfig, P2pConfig as MalachiteBftP2pConfig,
};

// --- Malachite Core Types ---
// NodeKey is directly from malachitebft_core_types
use malachitebft_core_types::NodeKey;
// The fundamental Context trait, if needed for deeper generic bounds, though AppChannelContext should be primary.
// use malachitebft_core_types::Context as MalachiteCoreContextTrait;

// --- Malachite Test Types (for concrete implementations of traits) ---
use malachitebft_test::{
    Address as TestAddress,
    // TestContext is an impl of MalachiteCoreContextTrait, not necessarily MalachiteAppChannelContext
    // Context as TestContext,
    Ed25519Provider,
    Extension as TestExtension,
    Genesis as TestGenesis,
    Height as TestHeight,
    Keypair as TestKeypair, // This type was unresolved, check if it's part of malachitebft-test's public API
    PrivateKey as TestPrivateKey,
    Proposal as TestProposal,
    ProposalPart as TestProposalPart,
    PublicKey as TestPublicKey,
    Validator as TestValidator,
    ValidatorSet as TestValidatorSet,
    Value as TestValue,
    Vote as TestVote,
    codec::proto::ProtobufCodec,
    streaming::StreamContent,
};

// --- Placeholder for Malachite's Top-Level Config ---
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MalachiteTopLevelConfig {
    pub moniker: String,
    pub home: PathBuf,
    pub genesis_file: PathBuf,
    pub priv_validator_key_file: PathBuf,
    pub node_key_file: PathBuf,
    pub p2p: MalachiteBftP2pConfig,
    pub consensus: MalachiteBftConsensusConfig,
}
impl MalachiteTopLevelConfig {
    pub fn load_toml_file<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let config_str = fs::read_to_string(path.as_ref())?;
        toml::from_str(&config_str).map_err(anyhow::Error::from)
    }
}

#[derive(Clone, Debug)]
pub struct AuraMalachiteContext;

impl MalachiteAppChannelContext for AuraMalachiteContext {
    type Address = TestAddress;
    type Height = TestHeight;
    type ProposalPart = TestProposalPart;
    type Proposal = TestProposal;
    type Validator = TestValidator;
    type ValidatorSet = TestValidatorSet;
    type Value = AuraInternalBlock;
    type Vote = TestVote;
    type Extension = TestExtension;
    type SigningScheme = Ed25519Provider;

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
        let seed = height.as_u64().wrapping_add(round.as_u32() as u64);
        let mut proposer_index = 0;
        let mut accumulated_power = 0u64;

        let validators = validator_set.validators(); // Get slice of validators
        if validators.is_empty() {
            panic!("Validator set is empty, cannot select proposer.");
        }

        for (i, val) in validators.iter().enumerate() {
            accumulated_power = accumulated_power.wrapping_add(val.power());
            // Changed clippy suggestion from `>` to `>=` because `seed % total_power` can be 0
            // and `+1` ensures we always pick someone if total_power > 0.
            // If `seed % total_power` is 0, `(seed % total_power) + 1` is 1.
            // Smallest accumulated_power can be (if first validator has power > 0) is val.power().
            // This logic might need more careful review against Tendermint's actual weighted round robin.
            if accumulated_power > (seed % total_power) {
                proposer_index = i;
                break;
            }
        }
        validators.get(proposer_index).unwrap_or_else(|| {
            // Fallback if something went wrong, though with total_power > 0 and validators non-empty, this shouldn't happen.
            warn!("Proposer selection fallback to first validator.");
            validators
                .first()
                .expect("Validator set confirmed non-empty but failed to get fallback proposer")
        })
    }

    fn new_proposal(
        height: Self::Height,
        round: Round,
        value: Self::Value,
        pol_round: Round,
        address: Self::Address,
    ) -> Self::Proposal {
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

impl MalachiteValueTrait for AuraInternalBlock {
    type Id = u64;
    fn id(&self) -> Self::Id {
        self.height
    }
}

#[derive(Clone)]
pub struct AuraNode {
    pub home_dir: PathBuf,
    pub aura_app_config: AuraAppNodeConfig,
    pub malachite_config_path: PathBuf,
    _app_level_private_key: Arc<aura_core::PrivateKey>,
}

pub struct AuraNodeRunningHandle {
    pub app_logic_handle: JoinHandle<()>, // Corrected: tokio::task::JoinHandle
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
    type Config = MalachiteTopLevelConfig;
    type Genesis = TestGenesis;
    type PrivateKeyFile = TestPrivateKey;
    type SigningProvider = Ed25519Provider;
    // Corrected: Ambiguous associated type
    type NodeHandle = AuraNodeRunningHandle;

    fn get_home_dir(&self) -> PathBuf {
        self.home_dir.clone()
    }

    fn load_config(&self) -> eyre::Result<Self::Config> {
        MalachiteTopLevelConfig::load_toml_file(&self.malachite_config_path)
            .map_err(|e| eyre!("Failed to load Malachite config: {}", e))
    }

    fn get_address(&self, pk: &TestPublicKey) -> TestAddress {
        TestAddress::from_public_key(pk)
    }

    fn get_public_key(&self, pk: &Self::PrivateKeyFile) -> TestPublicKey {
        pk.public_key()
    }

    // Check if TestKeypair is part of malachitebft-test's public API for this rev
    // If not, this method might need to be removed or adapted if Malachite doesn't require it.
    // The tutorial showed it, so it's likely available.
    fn get_keypair(&self, pk: Self::PrivateKeyFile) -> TestKeypair {
        TestKeypair::ed25519_from_bytes(pk.inner().to_bytes())
            .expect("Failed to create keypair from TestPrivateKey bytes")
    }

    fn load_private_key(&self, file_content: Self::PrivateKeyFile) -> TestPrivateKey {
        file_content
    }

    fn load_private_key_file(&self) -> eyre::Result<Self::PrivateKeyFile> {
        let config = self.load_config()?;
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
        // Corrected associated type
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

        let app_state_db_path = self.get_home_dir().join(
            &self
                .aura_app_config
                .db_path
                .file_name()
                .expect("App DB path should have a filename"),
        );
        fs::create_dir_all(app_state_db_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let app_state = AuraState::new(app_state_db_path, self._app_level_private_key.clone())
            .map_err(|e| eyre!("Failed to create AuraState: {}", e))?; // Convert AuraError to eyre::Report
        let app_state_arc = Arc::new(Mutex::new(app_state));

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
        let node_key: NodeKey = serde_json::from_str(&node_key_str).map_err(|e| {
            eyre!(
                "Failed to parse P2P node_key file from {:?}: {}",
                node_key_path,
                e
            )
        })?;
        info!("Loaded P2P NodeKey: {}", node_key.public_key().to_string());

        info!("Calling malachitebft_app_channel::start_engine...");
        let (channels, engine_handle) = malachite_start_engine(
            // Use imported function
            aura_malachite_ctx.clone(),
            codec,
            priv_validator_key,
            node_key,
            malachite_config.clone(),
            None,
            initial_validator_set,
        )
        .await?; // Removed `mut` from channels as it's moved into the spawned task
        info!("Malachite engine started via app-channel.");

        let tx_event_channel = channels.events.clone();
        let app_logic_task_span =
            tracing::info_span!("app_message_loop", moniker = %malachite_config.moniker);
        let app_logic_handle = tokio::spawn(
            // Corrected: tokio::spawn
            app_message_loop(app_state_arc, aura_malachite_ctx, channels) // Pass channels by value (move)
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

async fn app_message_loop(
    app_state_arc: Arc<Mutex<AuraState>>,
    _ctx: AuraMalachiteContext,
    mut channels: Channels<AuraMalachiteContext>,
) -> eyre::Result<()> {
    info!("Application message loop started. Waiting for messages from consensus...");
    loop {
        tokio::select! {
            Some(msg) = channels.consensus.recv() => {
                debug!("AppLoop: Received AppMsg from consensus: {}", msg_type_name(&msg));
                match msg {
                    AppMsg::ConsensusReady { reply, .. } => {
                        let mut state = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed for ConsensusReady: {}", e))?;
                        let start_height = if state.height_value() == 0 {
                            TestHeight::new(1)
                        } else {
                            TestHeight::new(state.height_value() + 1)
                        };
                        let validator_set = TestValidatorSet::new(vec![]);
                        info!(%start_height, "AppLoop: Consensus is ready. Replying with StartHeight.");
                        if reply.send((start_height, validator_set)).is_err() {
                            error!("AppLoop: Failed to send ConsensusReady reply (StartHeight)");
                        }
                    }
                    AppMsg::StartedRound { height, round, proposer, reply_value } => {
                        let mut state_guard = app_state_arc.lock().map_err(|e| eyre!("Mutex lock failed for StartedRound: {}", e))?;
                        state_guard.current_height = height.as_u64();
                        state_guard.current_round = round;
                        // state_guard.current_proposer = Some(proposer.to_string()); // Assuming proposer can be stringified
                        info!(%height, %round, %proposer, "AppLoop: Started round.");
                         if reply_value.send(None).is_err() {
                            error!("AppLoop: Failed to send reply for StartedRound (value reply)");
                         }
                    }
                    AppMsg::GetValue { height, round, reply, .. } => {
                        info!(%height, %round, "AppLoop: Consensus requesting a value (block) to propose.");
                        // let mut state_guard = app_state_arc.lock().map_err(|e| eyre!("Mutex lock for GetValue: {}", e))?;

                        let new_aura_block = AuraInternalBlock {
                            height: height.as_u64(),
                            proposer_address: "aura_node_self_proposing".to_string(),
                            timestamp: chrono::Utc::now().timestamp(),
                            transactions: vec![],
                        };

                        let locally_proposed_value = LocallyProposedValue {
                            height,
                            round,
                            value: new_aura_block.clone(),
                        };

                        if reply.send(locally_proposed_value).is_err() {
                            error!("AppLoop: Failed to send GetValue reply (LocallyProposedValue)");
                        }

                        warn!("AppLoop: TODO: Implement streaming of AuraInternalBlock as TestProposalParts for GetValue");
                        // Conceptual streaming logic:
                        // let stream_id = StreamId::new(format!("{}-{}", height.as_u64(), round.as_u32()).into_bytes()); // Example stream ID
                        // let parts: Vec<TestProposalPart> = vec![TestProposalPart::Data(malachitebft_test::ProposalData::new(new_aura_block.id() as u64))]; // Simplified part
                        //
                        // for (seq, part_content) in parts.into_iter().enumerate() {
                        //    let stream_msg = malachitebft_app_channel::app::types::streaming::StreamMessage::new(stream_id.clone(), seq as u64, StreamContent::Data(part_content));
                        //    if channels.network.send(NetworkMsg::PublishProposalPart(stream_msg)).await.is_err() {
                        //        error!("AppLoop: Failed to send proposal part to network");
                        //    }
                        // }
                        // let fin_msg = malachitebft_app_channel::app::types::streaming::StreamMessage::new(stream_id, parts.len() as u64, StreamContent::Fin);
                        // if channels.network.send(NetworkMsg::PublishProposalPart(fin_msg)).await.is_err() { error!("Failed to send Fin part"); }

                    }
                    AppMsg::ReceivedProposalPart { from, part, reply } => {
                        let part_type_str = match &part.content {
                            StreamContent::Data(p) => format!("{:?}", p),
                            StreamContent::Fin => "Fin".to_string(),
                        };
                        info!(peer_id = %from, sequence = %part.sequence, part_type = %part_type_str, "AppLoop: Received proposal part.");
                        // TODO: Accumulate parts and reconstruct AuraInternalBlock
                        if reply.send(None).is_err() {
                             error!("AppLoop: Failed to send ReceivedProposalPart reply");
                        }
                    }
                    AppMsg::Decided { certificate, extensions: _, reply } => {
                        info!(height = %certificate.height, round = %certificate.round, value_id = %certificate.value_id, "AppLoop: Consensus decided. Committing block.");
                        let mut state_guard = app_state_arc.lock().map_err(|e| eyre!("Mutex lock for Decided: {}", e))?;

                        // We need to ensure AuraState's pending_block_height was set correctly before commit.
                        // This typically happens in AuraState::begin_block, which should be triggered by
                        // the consensus engine before it proposes/receives a block for this height.
                        // The `AppMsg::StartedRound` sets `state_guard.current_height`.
                        // `AuraState::begin_block` uses `current_height + 1`.
                        // So when `Decided` arrives for `certificate.height`, `AuraState::pending_block_height`
                        // should already match `certificate.height` if `BeginBlock` was called for this height.
                        if certificate.height.as_u64() != state_guard.pending_block_height {
                             error!("AppLoop: Decided height {} does not match pending block height {}. This indicates a potential state mismatch or missed BeginBlock call.",
                                certificate.height.as_u64(), state_guard.pending_block_height);
                             // This is a serious issue. For now, we proceed but it needs investigation.
                        }


                        match state_guard.commit_block() {
                            Ok(_app_hash) => {
                                let next_height = TestHeight::new(state_guard.height_value() + 1);
                                let validator_set = TestValidatorSet::new(vec![]);
                                info!("AppLoop: Commit successful. Replying to start next height: {}", next_height);
                                if reply.send(ConsensusMsg::StartHeight(next_height, validator_set)).is_err() {
                                    error!("AppLoop: Failed to send Decided reply (StartHeight)");
                                }
                            }
                            Err(e) => {
                                error!("AppLoop: Commit failed after Decided: {:?}. Requesting restart for height {}.", e, state_guard.pending_block_height);
                                let current_pending_height = TestHeight::new(state_guard.pending_block_height);
                                let validator_set = TestValidatorSet::new(vec![]);
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
                        let vs_placeholder = TestValidatorSet::new(vec![]);
                        if reply.send(vs_placeholder).is_err() {
                            error!("AppLoop: Failed to send GetValidatorSet reply");
                        }
                    }
                    AppMsg::GetHistoryMinHeight { reply } => {
                         info!("AppLoop: GetHistoryMinHeight called");
                        let min_h_placeholder = TestHeight::new(0);
                        if reply.send(min_h_placeholder).is_err() {
                             error!("AppLoop: Failed to send GetHistoryMinHeight reply");
                        }
                    }
                     AppMsg::GetDecidedValue { height, reply } => {
                        info!("AppLoop: GetDecidedValue called for height {}", height);
                        if reply.send(None).is_err() {
                            error!("AppLoop: Failed to send GetDecidedValue reply");
                        }
                    }
                    AppMsg::ProcessSyncedValue { height, round, proposer, value_bytes, reply } => {
                        info!(%height, %round, "AppLoop: Processing synced value ({} bytes)", value_bytes.len());
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

fn msg_type_name<C: MalachiteAppChannelContext>(msg: &AppMsg<C>) -> &'static str {
    // Corrected Trait bound
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
