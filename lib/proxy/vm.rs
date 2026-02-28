use crate::proxy::udp_packet_helper::UdpPacketHelper;
use crate::proxy::{Action, Proxy};
use anyhow::Context;
use anyhow::Result;
use ipnet::Ipv4Net;
use smoltcp::wire::{
    ArpPacket, EthernetAddress, EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address,
    Ipv4Packet, UdpPacket,
};
use std::net::Ipv4Addr;

impl Proxy<'_> {
    pub(crate) fn process_frame_from_vm(&mut self, frame: EthernetFrame<&[u8]>) -> Result<()> {
        if self.allowed_from_vm(&frame).is_none() {
            // For blocked DNS queries, send an immediate NXDOMAIN response
            // instead of silently dropping (which causes the client to timeout)
            let _ = self.try_send_dns_nxdomain(&frame);
            return Ok(());
        }

        self.host
            .write(frame.as_ref())
            .map(|_| ())
            .context("failed to write to the host")
    }

    /// When a DNS query from the VM is blocked, synthesize an NXDOMAIN response
    /// and write it back to the VM so the client receives an immediate error.
    fn try_send_dns_nxdomain(&mut self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
        // Only respond to packets from our VM
        if frame.src_addr() != self.vm_mac_address {
            return None;
        }
        if frame.ethertype() != EthernetProtocol::Ipv4 {
            return None;
        }
        let ipv4_pkt = Ipv4Packet::new_checked(frame.payload()).ok()?;
        if ipv4_pkt.next_header() != IpProtocol::Udp {
            return None;
        }
        let udp_pkt = UdpPacket::new_checked(ipv4_pkt.payload()).ok()?;
        if !udp_pkt.is_dns_request() {
            return None;
        }

        let response = build_nxdomain_frame(
            frame.src_addr(),    // VM MAC  → dst of response
            frame.dst_addr(),    // GW MAC  → src of response
            ipv4_pkt.src_addr(), // VM IP   → dst of response
            ipv4_pkt.dst_addr(), // DNS IP  → src of response
            udp_pkt.src_port(),  // VM port → dst port of response
            udp_pkt.payload(),   // DNS query bytes
        )?;

        self.vm.write(&response).ok()?;
        Some(())
    }

    fn allowed_from_vm(&self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
        if frame.src_addr() != self.vm_mac_address {
            return None;
        }

        match frame.ethertype() {
            EthernetProtocol::Arp => {
                let arp_pkt = ArpPacket::new_checked(frame.payload()).ok()?;
                self.allowed_from_vm_arp(arp_pkt)
            }
            EthernetProtocol::Ipv4 => {
                let ipv4_pkt = Ipv4Packet::new_checked(frame.payload()).ok()?;
                self.allowed_from_vm_ipv4(ipv4_pkt)
            }
            _ => None,
        }
    }

    fn allowed_from_vm_arp(&self, arp_pkt: ArpPacket<&[u8]>) -> Option<()> {
        if arp_pkt.source_hardware_addr() != self.vm_mac_address.0 {
            return None;
        }

        let source_protocol_addr: [u8; 4] = arp_pkt.source_protocol_addr().try_into().unwrap();
        let source_protocol_addr = Ipv4Addr::from(source_protocol_addr);

        if let Some(lease) = self.dhcp_snooper.lease() {
            if lease.valid_ip_source(source_protocol_addr) {
                return Some(());
            }
        } else if source_protocol_addr.is_unspecified() {
            return Some(());
        }

        None
    }

    pub(crate) fn allowed_from_vm_ipv4(&self, ipv4_pkt: Ipv4Packet<&[u8]>) -> Option<()> {
        // Is this packet coming from VM's IP address that we've learned from DHCP snooping?
        if let Some(lease) = &self.dhcp_snooper.lease()
            && lease.valid_ip_source(ipv4_pkt.src_addr())
        {
            let dst_addr = ipv4_pkt.dst_addr();

            // Filter traffic based on user-specified rules first
            if !self.rules.is_empty() {
                let dst_net = Ipv4Net::from(dst_addr);

                if let Some((_, action)) = self.rules.get_lpm(&dst_net) {
                    return match action {
                        Action::Allow => Some(()),
                        Action::Block => None,
                    };
                }
            }

            // When dns_filter is active, allow traffic only to learned IPs
            if let Some(dns_filter) = &self.dns_filter {
                if dns_filter.is_learned_ip(&dst_addr) {
                    return Some(());
                }
            } else if ip_network::IpNetwork::from(dst_addr).is_global() {
                // When no user-specified rules matched and no dns_filter,
                // simply allow all global traffic
                return Some(());
            }

            // Additionally, allow DNS requests to DNS-servers
            // provided to a VM by the host's DHCP server.
            // This check must come BEFORE the gateway check so that
            // when dns_filter is active, DNS queries to the gateway
            // (which is also the DNS server) are still domain-filtered.
            if ipv4_pkt.next_header() == IpProtocol::Udp {
                if let Ok(udp_pkt) = UdpPacket::new_checked(ipv4_pkt.payload()) {
                    if udp_pkt.is_dns_request()
                        && self.dhcp_snooper.valid_dns_target(&ipv4_pkt.dst_addr())
                    {
                        // When dns_filter is active, check the queried domain
                        if let Some(dns_filter) = &self.dns_filter {
                            let domain_allowed =
                                crate::dns_filter::DnsFilter::extract_query_domain(
                                    udp_pkt.payload(),
                                )
                                .map(|domain| dns_filter.is_domain_allowed(&domain))
                                .unwrap_or(false);
                            if domain_allowed {
                                return Some(());
                            } else {
                                return None; // Explicitly block disallowed DNS queries
                            }
                        } else {
                            return Some(());
                        }
                    }
                }
            }

            // Additionally, allow communication with the host,
            // otherwise things like SSH to a VM won't work.
            // Non-DNS traffic to the gateway is always allowed.
            if ipv4_pkt.dst_addr() == self.host.gateway_ip {
                return Some(());
            }
        }

        // Allow outgoing DHCP requests to broadcast addresses,
        // otherwise DHCP snooper will never be populated
        if ipv4_pkt.next_header() == IpProtocol::Udp {
            let udp_pkt = UdpPacket::new_checked(ipv4_pkt.payload()).ok()?;

            // Allow DHCP communication with the bootpd(8) on host via broadcast address
            if udp_pkt.is_dhcp_request() && ipv4_pkt.dst_addr().is_broadcast() {
                return Some(());
            }
        }

        None
    }
}

/// Build a complete Ethernet/IPv4/UDP frame containing a DNS NXDOMAIN response.
fn build_nxdomain_frame(
    dst_mac: EthernetAddress,
    src_mac: EthernetAddress,
    dst_ip: Ipv4Address,
    src_ip: Ipv4Address,
    dst_port: u16,
    dns_query: &[u8],
) -> Option<Vec<u8>> {
    let dns_resp = build_dns_nxdomain(dns_query)?;
    let udp_len: usize = 8 + dns_resp.len();
    let ip_len: usize = 20 + udp_len;
    let frame_len: usize = 14 + ip_len;

    let mut buf = vec![0u8; frame_len];

    // Ethernet header (14 bytes)
    buf[0..6].copy_from_slice(&dst_mac.0);   // dst MAC
    buf[6..12].copy_from_slice(&src_mac.0);  // src MAC
    buf[12] = 0x08;                           // EtherType: IPv4 (0x0800)
    buf[13] = 0x00;

    // IPv4 header (20 bytes at offset 14)
    buf[14] = 0x45;                           // Version=4, IHL=5 (20 bytes)
    // buf[15] = 0x00;                        // DSCP=0, ECN=0
    let ip_total = ip_len as u16;
    buf[16] = (ip_total >> 8) as u8;
    buf[17] = ip_total as u8;
    // buf[18..20] = 0                        // Identification
    buf[20] = 0x40;                           // Flags: DF=1
    // buf[21] = 0x00;                        // Fragment offset
    buf[22] = 64;                             // TTL
    buf[23] = 0x11;                           // Protocol: UDP
    // buf[24..26] = checksum (filled below)
    buf[26..30].copy_from_slice(&src_ip.octets());  // src IP (DNS server)
    buf[30..34].copy_from_slice(&dst_ip.octets());  // dst IP (VM)
    let cksum = ipv4_checksum(&buf[14..34]);
    buf[24] = (cksum >> 8) as u8;
    buf[25] = cksum as u8;

    // UDP header (8 bytes at offset 34)
    buf[34] = 0x00;                           // src port: 53 (high)
    buf[35] = 0x35;                           // src port: 53 (low)
    buf[36] = (dst_port >> 8) as u8;
    buf[37] = dst_port as u8;
    let udp_total = udp_len as u16;
    buf[38] = (udp_total >> 8) as u8;
    buf[39] = udp_total as u8;
    // buf[40..42] = 0                        // UDP checksum (optional for IPv4)

    // DNS payload (at offset 42)
    buf[42..42 + dns_resp.len()].copy_from_slice(&dns_resp);

    Some(buf)
}

/// Build a minimal DNS NXDOMAIN response body from a raw DNS query.
fn build_dns_nxdomain(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let rd = query[2] & 0x01; // Recursion Desired bit from query flags

    let mut resp = Vec::with_capacity(query.len());
    resp.extend_from_slice(&query[0..2]);         // Transaction ID
    resp.push(0x80 | rd);                         // QR=1, OPCODE=0, AA=0, TC=0, RD=copy
    resp.push(0x83);                              // RA=1, Z=0, RCODE=3 (NXDOMAIN)
    resp.extend_from_slice(&query[4..6]);         // QDCOUNT (copy from query)
    resp.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    resp.extend_from_slice(&query[12..]);         // Question section
    Some(resp)
}

/// Compute the one's complement checksum for an IPv4 header.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
