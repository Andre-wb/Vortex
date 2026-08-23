use serde::{Deserialize, Serialize};

pub const MESH: &str = "mesh";
pub const SFU: &str = "sfu";
pub const MESH_MAX_PARTICIPANTS: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Topology {
    #[serde(rename = "mesh")]
    Mesh,
    #[serde(rename = "sfu")]
    Sfu,
}

impl Topology {
    pub fn chosen(sfu_available: bool, members: u32, threshold: u32) -> Self {
        if sfu_available && members > threshold {
            return Topology::Sfu;
        }
        Topology::Mesh
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Topology::Mesh => MESH,
            Topology::Sfu => SFU,
        }
    }

    pub fn max_participants(self, sfu_max: u32) -> u32 {
        match self {
            Topology::Mesh => MESH_MAX_PARTICIPANTS,
            Topology::Sfu => sfu_max,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Topology, MESH_MAX_PARTICIPANTS};

    #[test]
    fn a_small_room_stays_on_the_mesh_where_media_is_end_to_end() {
        assert_eq!(Topology::chosen(true, 6, 6), Topology::Mesh);
        assert_eq!(
            Topology::chosen(true, 6, 6).max_participants(200),
            MESH_MAX_PARTICIPANTS
        );
    }

    #[test]
    fn a_room_above_the_threshold_moves_to_the_forwarding_unit() {
        assert_eq!(Topology::chosen(true, 7, 6), Topology::Sfu);
        assert_eq!(Topology::chosen(true, 7, 6).max_participants(200), 200);
    }

    #[test]
    fn without_a_forwarding_unit_every_room_stays_on_the_mesh() {
        assert_eq!(Topology::chosen(false, 500, 6), Topology::Mesh);
    }

    #[test]
    fn a_topology_survives_the_trip_back_to_the_client() {
        assert_eq!(Topology::Mesh.as_str(), "mesh");
        assert_eq!(Topology::Sfu.as_str(), "sfu");
    }
}
