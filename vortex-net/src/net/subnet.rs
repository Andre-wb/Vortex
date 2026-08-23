use crate::net::GLOBAL_BROADCAST;

pub fn subnet_broadcast(ip: &str) -> String {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() == 4 {
        format!("{}.{}.{}.255", octets[0], octets[1], octets[2])
    } else {
        GLOBAL_BROADCAST.to_string()
    }
}
