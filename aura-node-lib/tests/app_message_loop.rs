use aura_node_lib::AuraState;
use aura_node_lib::node::app_message_loop;
use bytes::Bytes;
use libp2p::identity::{Keypair, PeerId as Libp2pPeerId};
use malachitebft_app_channel::{AppMsg, Channels, ConsensusMsg, NetworkMsg};
use malachitebft_core_types::{Round, Validity, VotingPower};
use malachitebft_engine::util::events::TxEvent;
use malachitebft_engine::util::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_peer::PeerId;
use malachitebft_signing_ed25519::{PrivateKey as Ed25519PrivateKey, Signature};
use malachitebft_test::{
    Address as TestAddress, Ed25519Provider, Height as TestHeight, ProposalFin, ProposalInit,
    ProposalPart, TestContext, Validator, ValidatorSet as TestValidatorSet, Value as TestValue,
};
use rand::thread_rng;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

struct TestEnv {
    cons_tx: mpsc::Sender<AppMsg<TestContext>>,
    net_rx: mpsc::Receiver<NetworkMsg<TestContext>>,
    state: Arc<Mutex<AuraState>>,
    handle: tokio::task::JoinHandle<eyre::Result<()>>,
    addr: TestAddress,
    validators: TestValidatorSet,
}

impl TestEnv {
    async fn shutdown(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

async fn setup() -> TestEnv {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("state.db");
    let priv_key = aura_core::keys::PrivateKey::new_random();
    let state = AuraState::new(&db_path, Arc::new(priv_key.clone())).unwrap();
    let state_arc = Arc::new(Mutex::new(state));

    let (cons_tx, cons_rx) = mpsc::channel(8);
    let (net_tx, net_rx) = mpsc::channel(8);
    let event_tx = TxEvent::new();

    let channels = Channels {
        consensus: cons_rx,
        network: net_tx,
        events: event_tx,
    };
    let ctx = TestContext::default();

    let sk = Ed25519PrivateKey::generate(thread_rng());
    let validator = Validator::new(sk.public_key(), 1 as VotingPower);
    let validators = TestValidatorSet::new(vec![validator]);
    let signing = Ed25519Provider::new(sk);
    let addr = TestAddress::from_public_key(&signing.private_key().public_key());

    let handle = tokio::spawn(app_message_loop(
        state_arc.clone(),
        ctx,
        channels,
        validators.clone(),
        signing,
        addr,
    ));

    TestEnv {
        cons_tx,
        net_rx,
        state: state_arc,
        handle,
        addr,
        validators,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_get_history_min_height() {
    let env = setup().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::GetHistoryMinHeight { reply: reply_tx })
        .await
        .unwrap();
    let res = reply_rx.await.unwrap();
    assert_eq!(res, TestHeight::new(0));

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_consensus_ready() {
    let env = setup().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::ConsensusReady { reply: reply_tx })
        .await
        .unwrap();
    let (height, validators) = reply_rx.await.unwrap();
    assert_eq!(height, TestHeight::new(1));
    assert_eq!(validators, env.validators);

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_started_round() {
    let env = setup().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::StartedRound {
            height: TestHeight::new(1),
            round: Round::ZERO,
            proposer: env.addr,
            reply_value: reply_tx,
        })
        .await
        .unwrap();
    let vals = reply_rx.await.unwrap();
    assert!(vals.is_empty());

    {
        let state = env.state.lock().unwrap();
        assert_eq!(state.pending_block_height, 1);
        assert_eq!(state.current_round, Round::ZERO);
    }

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_get_value() {
    let mut env = setup().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::GetValue {
            height: TestHeight::new(1),
            round: Round::ZERO,
            timeout: Duration::from_secs(1),
            reply: reply_tx,
        })
        .await
        .unwrap();
    let proposed = reply_rx.await.unwrap();
    assert_eq!(proposed.height, TestHeight::new(1));
    assert_eq!(proposed.round, Round::ZERO);
    assert_eq!(proposed.value, TestValue::new(1));

    for _ in 0..4 {
        env.net_rx.recv().await.unwrap();
    }

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_extend_vote() {
    let env = setup().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::ExtendVote {
            height: TestHeight::new(1),
            round: Round::ZERO,
            value_id: TestValue::new(1).id(),
            reply: reply_tx,
        })
        .await
        .unwrap();
    let res = reply_rx.await.unwrap();
    assert!(res.is_none());

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_verify_vote_extension() {
    let env = setup().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::VerifyVoteExtension {
            height: TestHeight::new(1),
            round: Round::ZERO,
            value_id: TestValue::new(1).id(),
            extension: Bytes::new(),
            reply: reply_tx,
        })
        .await
        .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_restream_proposal() {
    let mut env = setup().await;

    env.cons_tx
        .send(AppMsg::RestreamProposal {
            height: TestHeight::new(1),
            round: Round::ZERO,
            valid_round: Round::ZERO,
            address: env.addr,
            value_id: TestValue::new(1).id(),
        })
        .await
        .unwrap();

    for _ in 0..4 {
        env.net_rx.recv().await.unwrap();
    }

    env.shutdown().await;
}

fn random_peer_id() -> PeerId {
    let kp = Keypair::generate_ed25519();
    let lib_id = Libp2pPeerId::from_public_key(&kp.public());
    PeerId::from_bytes(&lib_id.to_bytes()).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn test_received_proposal_part() {
    let env = setup().await;
    let peer = random_peer_id();
    let stream_id = StreamId::new(Bytes::from_static(b"abcd"));

    let init_part = ProposalPart::Init(ProposalInit::new(
        TestHeight::new(1),
        Round::ZERO,
        Round::Nil,
        env.addr,
    ));
    let msg = StreamMessage::new(stream_id.clone(), 0, StreamContent::Data(init_part));
    let (r_tx1, r_rx1) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::ReceivedProposalPart {
            from: peer,
            part: msg,
            reply: r_tx1,
        })
        .await
        .unwrap();
    assert!(r_rx1.await.unwrap().is_none());

    let fin_part = ProposalPart::Fin(ProposalFin::new(Signature::test()));
    let msg = StreamMessage::new(stream_id, 1, StreamContent::Data(fin_part));
    let (r_tx2, r_rx2) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::ReceivedProposalPart {
            from: peer,
            part: msg,
            reply: r_tx2,
        })
        .await
        .unwrap();
    let res = r_rx2.await.unwrap().unwrap();
    assert_eq!(res.height, TestHeight::new(1));
    assert_eq!(res.round, Round::ZERO);
    assert_eq!(res.value, TestValue::new(1));

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_get_validator_set() {
    let env = setup().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::GetValidatorSet {
            height: TestHeight::new(1),
            reply: reply_tx,
        })
        .await
        .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Some(env.validators.clone()));

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_decided() {
    let env = setup().await;

    let (r_tx, r_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::StartedRound {
            height: TestHeight::new(1),
            round: Round::ZERO,
            proposer: env.addr,
            reply_value: r_tx,
        })
        .await
        .unwrap();
    r_rx.await.unwrap();

    let certificate = malachitebft_core_types::CommitCertificate {
        height: TestHeight::new(1),
        round: Round::ZERO,
        value_id: TestValue::new(1).id(),
        commit_signatures: Vec::new(),
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::Decided {
            certificate,
            extensions: Default::default(),
            reply: reply_tx,
        })
        .await
        .unwrap();

    match reply_rx.await.unwrap() {
        ConsensusMsg::StartHeight(h, _) => assert_eq!(h, TestHeight::new(2)),
        _ => panic!("unexpected reply"),
    }

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_get_decided_value() {
    let env = setup().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::GetDecidedValue {
            height: TestHeight::new(1),
            reply: reply_tx,
        })
        .await
        .unwrap();
    assert!(reply_rx.await.unwrap().is_none());

    env.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_process_synced_value() {
    let env = setup().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    env.cons_tx
        .send(AppMsg::ProcessSyncedValue {
            height: TestHeight::new(1),
            round: Round::ZERO,
            proposer: env.addr,
            value_bytes: Bytes::new(),
            reply: reply_tx,
        })
        .await
        .unwrap();
    let res = reply_rx.await.unwrap();
    assert_eq!(res.validity, Validity::Invalid);

    env.shutdown().await;
}
