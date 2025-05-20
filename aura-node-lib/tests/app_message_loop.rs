use std::sync::{Arc, Mutex};
use aura_node_lib::state::AuraState;
use aura_node_lib::node::app_message_loop;
use malachitebft_app_channel::{Channels, AppMsg, NetworkMsg};
use malachitebft_test::{
    TestContext, ValidatorSet as TestValidatorSet, Address as TestAddress,
    Ed25519Provider, Height as TestHeight, Round as TestRound,
};
use tokio::sync::{mpsc, oneshot};

async fn setup() -> (
    Arc<Mutex<AuraState>>,
    mpsc::UnboundedSender<AppMsg<TestContext>>,
    mpsc::UnboundedReceiver<NetworkMsg<TestContext>>,
    tokio::task::JoinHandle<()>,
) {
    let temp_dir = tempfile::tempdir().unwrap();
    let priv_key = aura_core::keys::PrivateKey::new_random();
    let state = AuraState::new(temp_dir.path(), Arc::new(priv_key.clone())).unwrap();
    let state_arc = Arc::new(Mutex::new(state));

    let (cons_tx, cons_rx) = mpsc::unbounded_channel();
    let (net_tx, net_rx) = mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(16);

    let channels = Channels { consensus: cons_rx, network: net_tx, events: event_tx };
    let ctx = TestContext::default();
    let validators = TestValidatorSet::new();
    let signing = Ed25519Provider::new(priv_key);
    let addr = TestAddress::default();

    let handle = tokio::spawn(app_message_loop(state_arc.clone(), ctx, channels, validators, signing, addr));
    (state_arc, cons_tx, net_rx, handle)
}

#[tokio::test]
async fn test_get_history_min_height() {
    let (_state, cons_tx, _net_rx, handle) = setup().await;
    let (reply_tx, reply_rx) = oneshot::channel();
    cons_tx.send(AppMsg::GetHistoryMinHeight { reply: reply_tx }).unwrap();
    let res = reply_rx.await.unwrap();
    assert_eq!(res, TestHeight::new(0));
    handle.abort();
}

#[tokio::test]
async fn test_extend_and_verify_vote() {
    let (_state, cons_tx, _net_rx, handle) = setup().await;
    let (ext_tx, ext_rx) = oneshot::channel();
    cons_tx
        .send(AppMsg::ExtendVote { height: TestHeight::new(1), round: TestRound::new(1), reply: ext_tx })
        .unwrap();
    let sig = ext_rx.await.unwrap().unwrap();

    let (verify_tx, verify_rx) = oneshot::channel();
    cons_tx
        .send(AppMsg::VerifyVoteExtension {
            height: TestHeight::new(1),
            round: TestRound::new(1),
            extension: sig.clone(),
            address: TestAddress::default(),
            reply: verify_tx,
        })
        .unwrap();
    assert!(verify_rx.await.unwrap().is_ok());
    handle.abort();
}

#[tokio::test]
async fn test_get_decided_value_none() {
    let (_state, cons_tx, _net_rx, handle) = setup().await;
    let (reply_tx, reply_rx) = oneshot::channel();
    cons_tx
        .send(AppMsg::GetDecidedValue { height: TestHeight::new(1), reply: reply_tx })
        .unwrap();
    assert!(reply_rx.await.unwrap().is_none());
    handle.abort();
}

#[tokio::test]
async fn test_process_synced_value() {
    let (_state, cons_tx, _net_rx, handle) = setup().await;
    let (reply_tx, reply_rx) = oneshot::channel();
    cons_tx
        .send(AppMsg::ProcessSyncedValue {
            height: TestHeight::new(1),
            round: TestRound::new(1),
            proposer: TestAddress::default(),
            value_bytes: Vec::new(),
            reply: reply_tx,
        })
        .unwrap();
    let proposed = reply_rx.await.unwrap();
    assert_eq!(proposed.height, TestHeight::new(1));
    handle.abort();
}

#[tokio::test]
async fn test_restream_proposal() {
    let (_state, cons_tx, mut net_rx, handle) = setup().await;
    let (reply_tx, _reply_rx) = oneshot::channel();
    // request value to trigger streaming first
    cons_tx
        .send(AppMsg::GetValue {
            height: TestHeight::new(1),
            round: TestRound::new(1),
            valid_round: None,
            last_commit: None,
            reply: reply_tx,
        })
        .unwrap();
    // drain initial network messages
    for _ in 0..4 { net_rx.recv().await; }
    // restream
    cons_tx
        .send(AppMsg::RestreamProposal {
            height: TestHeight::new(1),
            round: TestRound::new(1),
            valid_round: None,
        })
        .unwrap();
    // expect at least one message
    assert!(net_rx.recv().await.is_some());
    handle.abort();
}
