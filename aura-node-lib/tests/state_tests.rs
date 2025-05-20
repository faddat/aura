use std::sync::Arc;
use tempfile::tempdir;

use aura_node_lib::state::AuraState;
use aura_core::{PrivateKey, Transaction, ZkProofData, Fee, Memo};

fn dummy_tx() -> Transaction {
    Transaction {
        spent_nullifiers: Vec::new(),
        new_note_commitments: Vec::new(),
        zk_proof_data: ZkProofData { proof_bytes: Vec::new() },
        fee: Fee(0),
        anchor: [0u8; 32],
        memo: Memo(Vec::new()),
    }
}

#[test]
fn test_min_height_and_get_block() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("db.redb");
    let pk = PrivateKey::new_random();
    let mut state = AuraState::new(&db_path, Arc::new(pk)).unwrap();

    state.begin_block(1, vec![1u8], 1).unwrap();
    state.deliver_tx(dummy_tx()).unwrap();
    state.end_block(1).unwrap();
    state.commit_block().unwrap();

    assert_eq!(state.min_height().unwrap(), 1);
    let block = state.get_block(1).unwrap();
    assert_eq!(block.height, 1);
    assert_eq!(block.transactions.len(), 1);

    // reopen state and ensure persistence
    drop(state);
    let pk2 = PrivateKey::new_random();
    let state2 = AuraState::new(&db_path, Arc::new(pk2)).unwrap();
    assert_eq!(state2.min_height().unwrap(), 1);
    let block2 = state2.get_block(1).unwrap();
    assert_eq!(block2.transactions.len(), 1);
}
