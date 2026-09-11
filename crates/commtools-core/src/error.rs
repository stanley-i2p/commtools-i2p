use crate::application::ApplicationCoordinatorError;
use crate::config::ConfigError;
use crate::crypto::CryptoError;
use crate::deaddrop::DeaddropError;
use crate::group_roster::GroupRosterError;
use crate::group_session::GroupSessionError;
use crate::ids::IdentifierError;
use crate::offline::OfflineError;
use crate::offline_coordinator::OfflineCoordinatorError;
use crate::one_to_one::OneToOneError;
use crate::private_group_invite::PrivateGroupInviteError;
use crate::protocol::ProtocolError;
use crate::rendezvous::RendezvousError;
use crate::sam::SamError;
use crate::storage::StorageError;
use crate::vault::VaultError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Application(#[from] ApplicationCoordinatorError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Deaddrop(#[from] DeaddropError),
    #[error(transparent)]
    GroupRoster(#[from] GroupRosterError),
    #[error(transparent)]
    GroupSession(#[from] GroupSessionError),
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    #[error(transparent)]
    Offline(#[from] OfflineError),
    #[error(transparent)]
    OfflineCoordinator(#[from] OfflineCoordinatorError),
    #[error(transparent)]
    OneToOne(#[from] OneToOneError),
    #[error(transparent)]
    PrivateGroupInvite(#[from] PrivateGroupInviteError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Rendezvous(#[from] RendezvousError),
    #[error(transparent)]
    Sam(#[from] SamError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Vault(#[from] VaultError),
}
