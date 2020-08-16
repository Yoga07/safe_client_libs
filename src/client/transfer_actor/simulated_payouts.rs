// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::TransferActor;
use crate::errors::CoreError;
use safe_nd::{Money, PublicKey};

use crate::ConnectionManager;
#[cfg(feature = "simulated-payouts")]
use {
    crate::client::create_cmd_message,
    log::info,
    safe_nd::{Cmd, Transfer, TransferCmd},
};

/// Handle all Money transfers and Write API requests for a given ClientId.
impl TransferActor {
    #[cfg(not(feature = "simulated-payouts"))]
    /// Simulate a farming payout
    pub async fn trigger_simulated_farming_payout(
        &mut self,
        _to: PublicKey,
        _amount: Money,
        _conn_mgr: &mut ConnectionManager,
    ) -> Result<(), CoreError> {
        Err(CoreError::from(
            "Simulated payouts not available without 'simulated-payouts' feature flag",
        ))
    }

    #[cfg(feature = "simulated-payouts")]
    /// Simulate a farming payout
    pub async fn trigger_simulated_farming_payout(
        &mut self,
        to: PublicKey,
        amount: Money,
        conn_mgr: &mut ConnectionManager,
    ) -> Result<(), CoreError> {
        info!("Triggering a simulated farming payout to: {:?}", &to);
        let safe_key = self.safe_key.clone();
        self.simulated_farming_payout_dot.apply_inc();

        let simulated_transfer = Transfer {
            to,
            amount,
            id: self.simulated_farming_payout_dot,
        };

        let simulated_farming_cmd =
            Cmd::Transfer(TransferCmd::SimulatePayout(simulated_transfer.clone()));

        let message = create_cmd_message(simulated_farming_cmd);

        // let pub_id = safe_key.public_id();

        let _bootstrapped = conn_mgr.bootstrap().await;
        let _ = conn_mgr.send_cmd(&message).await?;

        // If we're getting the payout for our own actor, update it here
        if to == self.safe_key.public_key() {
            info!("Applying simulated payout locally, via query for history...");

            // std::thread::sleep(std::time::Duration::from_millis(15500));

            // get full history from network and apply locally
            self.get_history(conn_mgr).await?;
        }
        Ok(())
    }
}

// --------------------------------
// Tests
// ---------------------------------

// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {

    use super::*;

    use crate::client::transfer_actor::test_utils::get_keys_and_connection_manager;
    use std::str::FromStr;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_can_receive_simulated_farming_payout() -> Result<(), CoreError> {
        let (safe_key, mut cm) = get_keys_and_connection_manager().await;
        let mut initial_actor =
            TransferActor::new_no_initial_balance(safe_key.clone(), &mut cm).await?;

        let _ = initial_actor
            .trigger_simulated_farming_payout(
                safe_key.public_key(),
                Money::from_str("100")?,
                &mut cm,
            )
            .await?;

        // 100 sent
        assert_eq!(
            initial_actor.get_local_balance().await,
            Money::from_str("100")?
        );

        assert_eq!(
            initial_actor
                .get_balance_from_network(None, &mut cm)
                .await?,
            Money::from_str("100")?
        );

        Ok(())
    }
}
