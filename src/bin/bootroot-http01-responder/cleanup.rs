//! Runs the background cleanup loop for expired HTTP-01 tokens.

use std::sync::Arc;

use tracing::info;

use super::state::ResponderState;

pub(super) async fn cleanup_expired_tokens(state: Arc<ResponderState>) {
    loop {
        tokio::time::sleep(state.cleanup_interval().await).await;
        let removed = state.purge_expired_tokens().await;
        if removed > 0 {
            info!("Removed {removed} expired HTTP-01 tokens");
        }
    }
}
