use std::net::{IpAddr, Ipv4Addr};

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn SendARP(dest_ip: u32, src_ip: u32, p_mac_addr: *mut u8, phy_addr_len: *mut u32) -> u32;
}

pub fn send_arp_probe(ip: Ipv4Addr) -> Option<String> {
    #[cfg(windows)]
    {
        let dest_ip = u32::from_ne_bytes(ip.octets());
        let mut mac = [0u8; 6];
        let mut len = 6u32;
        let res = unsafe { SendARP(dest_ip, 0, mac.as_mut_ptr(), &mut len) };
        if res == 0 && len == 6 {
            let mac_str = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
            if mac_str != "00:00:00:00:00:00" && mac_str != "FF:FF:FF:FF:FF:FF" {
                return Some(mac_str);
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = ip;
        None
    }
}

#[cfg_attr(not(feature = "admin"), allow(dead_code))]
pub fn resolve_mac(ip: &IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => send_arp_probe(*v4),
        IpAddr::V6(_) => None,
    }
}
