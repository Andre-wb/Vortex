use crate::prekey::identity::account::AccountIdentity;
use crate::prekey::identity::device::DeviceIdentity;
use crate::prekey::identity::kyber::DeviceKyberPreKey;
use crate::prekey::publish::one_time::OneTimePreKey;
use crate::prekey::publish::one_time_kyber::OneTimeKyberPreKey;
use crate::verify::complaint::Complaint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPublish {
    pub account: AccountIdentity,
    pub device: DeviceIdentity,
    pub kyber: DeviceKyberPreKey,
    pub supports_v2: Option<bool>,
    pub one_time: Vec<OneTimePreKey>,
    pub one_time_kyber: Vec<OneTimeKyberPreKey>,
    pub complaints: Vec<Complaint>,
}
