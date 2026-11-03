//! The Darkbloom provider agent for AMD machines. In production it runs
//! inside the sealed, measured Node OS; in the PoC it can also run on the
//! owner's development OS (clearly reported as such).

#![forbid(unsafe_code)]

pub mod agent;
pub mod status;

pub use agent::{Agent, Config, FatalError, StatusFn, VERSION};
pub use db_tpmdev::{AttestError, Attester};
pub use status::collect_status;
