use std::sync::Arc;

use vortex_transport::active_probe::store::memory_roll::MemoryRoll;
use vortex_transport::active_probe::store::memory_sightings::MemorySightings;
use vortex_transport::ports::probe_roll::ProbeRoll;
use vortex_transport::ports::probe_sightings::ProbeSightings;
use vortex_transport::testing::{probe_roll_conformance, probe_sightings_conformance};

#[test]
fn the_in_memory_sightings_satisfy_the_port_contract() {
    let make = |room: usize, memory: f64| -> Arc<dyn ProbeSightings> {
        Arc::new(MemorySightings::new(room, memory))
    };
    probe_sightings_conformance::check_all(&make);
}

#[test]
fn the_in_memory_roll_satisfies_the_port_contract() {
    let make = |room: usize, memory: f64| -> Arc<dyn ProbeRoll> {
        Arc::new(MemoryRoll::new(room, memory))
    };
    probe_roll_conformance::check_all(&make);
}
