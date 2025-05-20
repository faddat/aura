use std::sync::{Arc, Mutex};
use aura_node_lib::state::AuraState;
use aura_node_lib::node::{app_message_loop};
use malachitebft_app_channel::{Channels, AppMsg};
use malachitebft_test::{TestContext, ValidatorSet as TestValidatorSet, Address as TestAddress, Ed25519Provider, Height as TestHeight};
use tokio::sync::{mpsc, oneshot};

#[tokio::test]
async fn test_get_history_min_height() {
    let temp_dir = tempfile::tempdir().unwrap();
    let priv_key = aura_core::keys::PrivateKey::new_random();
    let state = AuraState::new(temp_dir.path(), Arc::new(priv_key.clone())).unwrap();
    let state_arc = Arc::new(Mutex::new(state));

    let (cons_tx, cons_rx) = mpsc::unbounded_channel();
    let (net_tx, _net_rx) = mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(16);

    let channels = Channels { consensus: cons_rx, network: net_tx, events: event_tx };
    let ctx = TestContext::default();
    let validators = TestValidatorSet::new();
    let signing = Ed25519Provider::new(priv_key);
    let addr = TestAddress::default();

    let handle = tokio::spawn(app_message_loop(state_arc.clone(), ctx, channels, validators.clone(), signing, addr));

    let (reply_tx, reply_rx) = oneshot::channel();
    cons_tx.send(AppMsg::GetHistoryMinHeight { reply: reply_tx }).unwrap();
    let res = reply_rx.await.unwrap();
    assert_eq!(res, TestHeight::new(0));

    handle.abort();
}
