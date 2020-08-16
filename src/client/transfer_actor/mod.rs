// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::{
    create_cmd_message, create_query_message, ConnectionManager, SafeKey, COST_OF_PUT,
};
use crate::errors::CoreError;
// use crdts::Dot;
use crdts::Dot;
use futures::lock::Mutex;
use log::{debug, info, warn};
use safe_nd::{
    Cmd, DebitAgreementProof, Message, PublicKey, Query, QueryResponse, TransferCmd, TransferQuery,
};
use safe_transfers::{
    ActorEvent, ReplicaValidator, TransferActor as SafeTransferActor, TransferInitiated,
};
use std::sync::Arc;
use threshold_crypto::PublicKeySet;

/// Module for Money balance management
pub mod balance_management;
/// Module for setting up SafeTransferActor
pub mod setup;
/// Module for simulating Money for testing
pub mod simulated_payouts;
/// Module containing all PUT apis
pub mod write_apis;

#[cfg(test)]
pub mod test_utils;

/// Handle Money Transfers, requests and locally stores a balance
#[derive(Clone)]
pub struct TransferActor {
    transfer_actor: Arc<Mutex<SafeTransferActor<ClientTransferValidator>>>,
    safe_key: SafeKey,
    replicas_pk_set: PublicKeySet,
    simulated_farming_payout_dot: Dot<PublicKey>,
}

/// Simple client side validations
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTransferValidator {}

impl ReplicaValidator for ClientTransferValidator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}

impl TransferActor {
    /// Get a payment proof
    pub async fn get_payment_proof(
        &mut self,
        conn_mgr: &mut ConnectionManager,
    ) -> Result<DebitAgreementProof, CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        self.create_write_payment_proof(conn_mgr).await
    }

    /// Retrieve the history of the acocunt from the network and apply to our local actor
    pub async fn get_history(&mut self, conn_mgr: &mut ConnectionManager) -> Result<(), CoreError> {
        let public_key = self.safe_key.public_key();
        info!("Getting SafeTransfers history for pk: {:?}", public_key);

        let msg_contents = Query::Transfer(TransferQuery::GetHistory {
            at: public_key,
            since_version: 0,
        });

        let message = create_query_message(msg_contents);

        let _bootstrapped = conn_mgr.bootstrap().await;

        // This is a normal response manager request. We want quorum on this for now...
        let res = conn_mgr.send_query(&message).await?;

        let history = match res {
            QueryResponse::GetHistory(history) => history.map_err(CoreError::from),
            _ => Err(CoreError::from(format!(
                "Unexpected response when retrieving account history {:?}",
                res
            ))),
        }?;

        let mut actor = self.transfer_actor.lock().await;
        match actor.synch(history) {
            Ok(synced_transfer_outcome) => {
                if let Some(transfers) = synced_transfer_outcome {
                    actor.apply(ActorEvent::TransfersSynched(transfers))?;
                }
            }
            Err(error) => {
                if !error
                    .clone()
                    .to_string()
                    .contains("No credits or debits found to sync to actor")
                {
                    return Err(CoreError::from(error));
                }

                warn!(
                    "No new transfer history  by TransferActor for pk: {:?}",
                    public_key
                );

                warn!("current balance {:?}", actor.balance());
            }
        }

        Ok(())
    }

    /// Validates a tranction for paying store_cost
    async fn create_write_payment_proof(
        &mut self,
        conn_mgr: &mut ConnectionManager,
    ) -> Result<DebitAgreementProof, CoreError> {
        info!("Sending requests for payment for write operation");

        self.get_history(conn_mgr).await?;

        let section_key = PublicKey::Bls(self.replicas_pk_set.public_key());
        // let mut actor = self.transfer_actor.lock().await;

        let signed_transfer = self
            .transfer_actor
            .lock()
            .await
            .transfer(COST_OF_PUT, section_key)?
            .ok_or_else(|| CoreError::from("No transfer produced by actor."))?
            .signed_transfer;

        let command = Cmd::Transfer(TransferCmd::ValidateTransfer(signed_transfer.clone()));

        debug!("Transfer to be sent: {:?}", &signed_transfer);

        let transfer_message = create_cmd_message(command);

        self.transfer_actor
            .lock()
            .await
            .apply(ActorEvent::TransferInitiated(TransferInitiated {
                signed_transfer,
            }))?;

        // setup connection manager
        let _bootstrapped = conn_mgr.bootstrap().await;

        let payment_proof: DebitAgreementProof =
            self.await_validation(&transfer_message, conn_mgr).await?;

        debug!("payment proof retrieved");
        Ok(payment_proof)
    }

    /// Send message and await validation and construction of DebitAgreementProof
    async fn await_validation(
        &mut self,
        message: &Message,
        conn_mgr: &mut ConnectionManager,
    ) -> Result<DebitAgreementProof, CoreError> {
        info!("Awaiting transfer validation");

        let proof = conn_mgr.send_for_validation(self, message).await?;

        Ok(proof)
    }
}

// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {

    use super::*;
    use test_utils::get_keys_and_connection_manager;

    #[tokio::test]
    async fn transfer_actor_creation__() {
        let (safe_key, mut cm) = get_keys_and_connection_manager().await;
        let _transfer_actor = TransferActor::new(safe_key, &mut cm).await.unwrap();

        assert!(true);
    }
}
