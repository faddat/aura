use std::sync::{Arc, Mutex};
use aura_node_lib::AuraState;
use aura_node_lib::node::app_message_loop;
use malachitebft_app_channel::{Channels, AppMsg};
use malachitebft_test::{
    TestContext, ValidatorSet as TestValidatorSet, Address as TestAddress,
    Ed25519Provider, Height as TestHeight, Validator,
};
use malachitebft_signing_ed25519::PrivateKey as Ed25519PrivateKey;
use malachitebft_core_types::VotingPower;
use tokio::sync::{mpsc, oneshot};
use rand::thread_rng;
use malachitebft_engine::util::events::TxEvent;

#[tokio::test]
async fn test_get_history_min_height() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("state.db");
    let priv_key = aura_core::keys::PrivateKey::new_random();
    let state = AuraState::new(&db_path, Arc::new(priv_key.clone())).unwrap();
    let state_arc = Arc::new(Mutex::new(state));

    let (cons_tx, cons_rx) = mpsc::channel(4);
    let (net_tx, _net_rx) = mpsc::channel(4);
    let event_tx = TxEvent::new();

    let channels = Channels { consensus: cons_rx, network: net_tx, events: event_tx };
    let ctx = TestContext::default();

    let sk = Ed25519PrivateKey::generate(&mut thread_rng());
    let validator = Validator::new(sk.public_key(), 1 as VotingPower);
    let validators = TestValidatorSet::new(vec![validator]);
    let signing = Ed25519Provider::new(sk);
    let addr = TestAddress::from_public_key(&signing.private_key().public_key());

    let handle = tokio::spawn(app_message_loop(state_arc.clone(), ctx, channels, validators.clone(), signing, addr));

    let (reply_tx, reply_rx) = oneshot::channel();
    cons_tx.send(AppMsg::GetHistoryMinHeight { reply: reply_tx }).await.unwrap();
    let res = reply_rx.await.unwrap();
    assert_eq!(res, TestHeight::new(0));

    handle.abort();
}
