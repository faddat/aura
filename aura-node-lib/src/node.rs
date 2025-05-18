use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::Result;
use crate::application::{AppService, AuraApplication};
use crate::config::AuraNodeConfig;
use crate::state::AuraState; // Uses AuraState from state.rs // Crate-local Result

const SIMULATION_BLOCK_INTERVAL_SECONDS: u64 = 5; // Produce a block every 5s in simulation
const HEARTBEAT_INTERVAL_SECONDS: u64 = 10 * 60; // 10 minutes for heartbeat block

pub struct AuraNode {
    app: Arc<AuraApplication>,
    // config: AuraNodeConfig, // Store if needed for other operations
}

impl AuraNode {
    pub fn new(config: AuraNodeConfig, node_private_key: aura_core::PrivateKey) -> Result<Self> {
        info!(
            "Initializing AuraNode with ID: {}, DB Path: {:?}",
            config.node_id, config.db_path
        );

        let aura_state = AuraState::new(&config.db_path, Arc::new(node_private_key))?;
        let app_state_arc = Arc::new(Mutex::new(aura_state));
        let aura_application = AuraApplication::new(app_state_arc, config.node_id.clone());

        Ok(AuraNode {
            app: Arc::new(aura_application),
            // config,
        })
    }

    pub async fn start_simulation_loop(self: Arc<Self>) -> Result<()> {
        info!("Starting single-node simulation loop...");
        let mut current_round: u64 = 0; // Simplified round for logging

        // For heartbeat block timing
        let mut last_block_time = tokio::time::Instant::now();

        loop {
            let current_height = match self.app.current_height().await {
                Ok(h) => h,
                Err(e) => {
                    error!("Simulation: Failed to get current height: {:?}", e);
                    sleep(Duration::from_secs(10)).await; // Wait before retrying
                    continue;
                }
            };
            let next_height = current_height + 1;

            // Determine if it's time for a heartbeat block or regular block
            let propose_reason =
                if last_block_time.elapsed().as_secs() >= HEARTBEAT_INTERVAL_SECONDS {
                    "heartbeat"
                } else {
                    // In a real system, we'd check for transactions.
                    // For simulation, we just proceed unless it's a heartbeat.
                    // The current `propose_block` will create empty blocks if mempool is empty.
                    "regular (or empty if no txs)"
                };

            info!(
                "Simulation: Attempting to propose {} block for height: {}, round: {}",
                propose_reason, next_height, current_round
            );

            match self.app.propose_block(next_height, current_round).await {
                Ok(block_proposal) => {
                    info!(
                        "Simulation: Proposed block successfully for height: {}. Transactions: {}",
                        block_proposal.height,
                        block_proposal.transactions.len()
                    );

                    match self.app.apply_block(block_proposal).await {
                        Ok(_) => {
                            info!(
                                "Simulation: Successfully applied block for height: {}",
                                next_height
                            );
                            last_block_time = tokio::time::Instant::now(); // Reset heartbeat timer
                        }
                        Err(e) => {
                            error!(
                                "Simulation: Failed to apply block for height {}: {:?}",
                                next_height, e
                            );
                            // For simulation, log and continue. In a real system, this might be fatal.
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Simulation: Failed to propose block for height {}: {:?}",
                        next_height, e
                    );
                    // This could happen due to state lock contention or other issues.
                }
            }

            current_round = current_round.wrapping_add(1);

            // Wait for the next block interval
            sleep(Duration::from_secs(SIMULATION_BLOCK_INTERVAL_SECONDS)).await;
        }
        // Loop is infinite, Ok(()) is not typically reached unless a shutdown mechanism is added.
        // For now, if it exits, it's an error path or unexpected.
        // warn!("Simulation loop unexpectedly exited.");
        // Ok(())
    }
}
