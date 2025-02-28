//! DAITA client implementation.
//!
//! This module implements DAITA as a state machine. It performs no blocking IO and is suitable to
//! run on a cooperative scheduler.

use maybenot;

/// DAITA state (including the Maybenot framework).
pub struct Daita<Machines, Rng> {
    maybenot: maybenot::Framework<Machines, Rng>,
}

/*
pub fn enable_daita() -> {

}
*/
