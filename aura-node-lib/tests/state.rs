use aura_node_lib::AuraState;
use std::sync::Arc;

#[test]
fn test_block_commit_and_retrieval() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("state.db");
    let priv_key = aura_core::keys::PrivateKey::new_random();
    let mut state = AuraState::new(&db_path, Arc::new(priv_key)).unwrap();

    state
        .begin_block(1, vec![], chrono::Utc::now().timestamp())
        .unwrap();
    state.commit_block().unwrap();

    assert_eq!(state.min_height().unwrap(), 1);
    let block = state.get_block(1).unwrap();
    assert_eq!(block.height, 1);
}
