//! DAITA client implementation.
//!
//! This module implements DAITA as a state machine. It performs no blocking IO and is suitable to
//! run on a cooperative scheduler.

use maybenot;

/// DAITA state (including the Maybenot framework).
pub struct Daita<Machines, Rng> {
    maybenot: maybenot::Framework<Machines, Rng>,
}

/// Inspiration: https://github.com/mullvad/wg-daita/blob/952a8c989037a2cf1c8966e504043e66beed5f47/src/daemon.rs#L98
pub struct Event<'a> {
    peer: &'a [u8; 32],
    machine: maybenot::Machine,
    event_type: maybenot::event::Event,
}

impl<Machines> Daita<Machines, rand_core::OsRng>
where
    Machines: AsRef<[maybenot::Machine]>,
{
    /// Initialize the maybenot framework with the provided machine.
    ///
    /// TODO: Handle errors properly
    pub fn start(
        machines: Machines,
        max_padding_bytes: f64,
        max_blocking_frac: f64,
    ) -> Option<Daita<Machines, rand_core::OsRng>> {
        // TODO: Make this modules sans-io?
        let now = std::time::Instant::now();
        // TODO: Make this modules sans-io?
        let rng = rand_core::OsRng;
        let maybenot =
            maybenot::Framework::new(machines, max_padding_bytes, max_blocking_frac, now, rng)
                .ok()?;

        let daita = Self { maybenot };

        Some(daita)
    }

    pub fn handle_event(&mut self, events: impl AsRef<[maybenot::event::TriggerEvent]>) {
        for action in self.event_to_actions(events) {
            match action {
                // DAITA V1
                maybenot::TriggerAction::Cancel { machine, timer } => todo!(),
                maybenot::TriggerAction::SendPadding {
                    timeout,
                    bypass,
                    replace,
                    machine,
                } => todo!(),
                // DAITA V2
                maybenot::TriggerAction::UpdateTimer {
                    duration,
                    replace,
                    machine,
                } => todo!(),
                maybenot::TriggerAction::BlockOutgoing {
                    timeout,
                    duration,
                    bypass,
                    replace,
                    machine,
                } => todo!(),
            }
        }
    }

    fn event_to_actions(
        &mut self,
        events: impl AsRef<[maybenot::event::TriggerEvent]>,
    ) -> impl Iterator<Item = &maybenot::TriggerAction> {
        // TODO: Make this modules sans-io?
        let now = std::time::Instant::now();
        self.maybenot.trigger_events(events.as_ref(), now)
    }
}

/*
pub fn enable_daita() -> {

}
*/
