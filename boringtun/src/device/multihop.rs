//! Multihop tunnel
//!
//! Encryption: Each packet is first encapsulated using the exit [Tunn]. An IP and UDP header that
//! point to the exit hop are added to the encapsulated packet, which is then encrypted using the
//! entry [Tunn].
//!
//! Decryption: The above is reversed. A packet is first decapsulated using the exit [Tunn], the
//! headers are stripped, and then the packet is decapsulated using the entry [Tunn].

// TODO: Allowed IPs, peers, what are those?
// TODO: NAT/route certain IPs via the entry at all times, so we don't need to switch tun

use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use etherparse::{PacketBuilder, SlicedPacket};
use rand_core::RngCore;

use crate::{
    noise::{rate_limiter::RateLimiter, Tunn, TunnResult},
    x25519,
};

pub enum AnyTunnel {
    Singlehop(Tunn),
    Multihop(MultihopTunnel),
}

impl AnyTunnel {
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        match self {
            AnyTunnel::Singlehop(tun) => tun.update_timers(dst),
            AnyTunnel::Multihop(tun) => tun.update_timers(dst),
        }
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        match self {
            AnyTunnel::Singlehop(tun) => tun.time_since_last_handshake(),
            AnyTunnel::Multihop(tun) => tun.time_since_last_handshake(),
        }
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        match self {
            AnyTunnel::Singlehop(tun) => tun.persistent_keepalive(),
            AnyTunnel::Multihop(tun) => tun.persistent_keepalive(),
        }
    }

    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        match self {
            AnyTunnel::Singlehop(tun) => tun.encapsulate(src, dst),
            AnyTunnel::Multihop(tun) => tun.encapsulate(src, dst),
        }
    }

    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        match self {
            AnyTunnel::Singlehop(tun) => tun.decapsulate(src_addr, datagram, dst),
            AnyTunnel::Multihop(tun) => tun.decapsulate(src_addr, datagram, dst),
        }
    }

    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        match self {
            AnyTunnel::Singlehop(tun) => tun.stats(),
            AnyTunnel::Multihop(tun) => tun.stats(),
        }
    }

    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        match self {
            AnyTunnel::Singlehop(tun) => {
                tun.set_static_private(static_private, static_public, rate_limiter)
            }
            AnyTunnel::Multihop(tun) => {
                tun.entry_tun.set_static_private(
                    static_private.clone(),
                    static_public,
                    rate_limiter,
                );
                //tun.exit_tun.set_static_private(static_private, static_public, None);
            }
        }
    }
}

pub struct MultihopTunnel {
    pub entry_tun: Tunn,
    pub exit_tun: Tunn,
    tunnel_ip: Ipv4Addr,
    exit_endpoint: SocketAddrV4,
    inner_tun_port: u16,
}

pub struct MultihopConfig {
    /// Private WireGuard key
    pub private_key: x25519::StaticSecret,
    /// Tunnel IP
    pub tunnel_ip: Ipv4Addr,
    /// Entry peer config
    pub entry_peer: x25519::PublicKey,
    /// Index of entry peer
    pub entry_idx: u32,
    /// Exit peer config
    pub exit_peer: PeerConfig,
    /// Index of exit peer
    pub exit_idx: u32,
}

pub struct PeerConfig {
    /// Public key of peer
    pub public_key: x25519::PublicKey,
    /// Peer endpoint
    pub endpoint: SocketAddrV4,
}

impl MultihopTunnel {
    pub fn new(config: MultihopConfig) -> Self {
        // TODO: index selection?

        let entry_tun = Tunn::new(
            config.private_key.clone(),
            config.entry_peer,
            None,
            None,
            config.entry_idx,
            None,
        );

        let exit_tun = Tunn::new(
            config.private_key,
            config.exit_peer.public_key,
            None,
            None,
            config.exit_idx,
            None,
        );

        let inner_tun_port = (40000 + rand_core::OsRng.next_u32() % (65000 - 40000)) as u16;
        log::debug!("Inner tun port: {inner_tun_port}");

        log::debug!("!!!");
        log::debug!("!!! Entry idx: {}", config.entry_idx);
        log::debug!("!!! Exit idx: {}", config.exit_idx);
        log::debug!("!!!");

        MultihopTunnel {
            entry_tun,
            exit_tun,
            tunnel_ip: config.tunnel_ip,
            exit_endpoint: config.exit_peer.endpoint,
            inner_tun_port,
        }
    }

    pub fn update_timers<'a>(&mut self, mut dst: &'a mut [u8]) -> TunnResult<'a> {
        // FIXME
        let mut horrible_dst = vec![0u8; dst.len()];

        // If the entry tun wants to write, return immediately
        match self.entry_tun.update_timers(&mut horrible_dst) {
            TunnResult::WriteToNetwork(packet) => {
                //log::debug!("!!!!");
                //log::debug!("!!!! entry -> update -> write to network");
                //log::debug!("!!!!");

                // Done! Send data directly to entry
                // TODO: fine to assume position is unchanged?
                let new_packet = &mut dst[..packet.len()];
                new_packet.copy_from_slice(&packet);
                return TunnResult::WriteToNetwork(new_packet);
            }
            // If exit wants nothing, continue with exit timers
            TunnResult::Done => (),
            TunnResult::Err(err) => return TunnResult::Err(err),
            _other => unreachable!("unexpected tunnel result from update_timers"),
        }

        // Encapsulate any traffic destined for the exit an extra time
        match self.exit_tun.update_timers(&mut dst) {
            TunnResult::WriteToNetwork(packet) => {
                //log::debug!("!!!!");
                //log::debug!("!!!! exit -> update -> write to network");
                //log::debug!("!!!!");

                // Encapsulate once more using entry hop
                let new_pkt = self.add_inner_ip_header(&mut horrible_dst, packet);
                self.entry_tun.encapsulate(new_pkt, dst)
            }
            TunnResult::Done => TunnResult::Done,
            TunnResult::Err(err) => TunnResult::Err(err),
            _other => unreachable!("unexpected tunnel result from update_timers"),
        }
    }

    /// Encapsulate a packet for the exit endpoint
    ///
    /// This function sends everything to the exit, by encapsulating data first using the exit tun
    /// and then the entry tun.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        // FIXME: do not encapsulate handshake initiation for entry...
        //        figure out if WriteToNetwork is due to handshake

        // FIXME
        let mut horrible_dst = vec![0u8; dst.len()];

        match self.exit_tun.encapsulate(src, dst) {
            TunnResult::Done => TunnResult::Done,
            TunnResult::Err(e) => TunnResult::Err(e),
            TunnResult::WriteToNetwork(packet) => {
                //log::debug!("!!!!");
                //log::debug!("!!!! exit -> enc -> write to network");
                //log::debug!("!!!!");

                // TODO
                // Encapsulate once more using entry hop
                let new_pkt = self.add_inner_ip_header(&mut horrible_dst, packet);
                self.entry_tun.encapsulate(new_pkt, dst)
                //TunnResult::WriteToNetwork(packet)
            }
            _ => panic!("Unexpected result from encapsulate"),
        }
    }

    /// Decapsulate a packet by first decrypting it with the exit, and then the entry, tun.
    ///
    /// In the case of `WriteToNetwork`, we must again encapsulate the data using the entry tun.
    ///
    /// In case of `WriteToTunnelV4` or `WriteToTunnelV6`, we must decapsulate it using the entry.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        // FIXME
        let mut horrible_dst = vec![0u8; dst.len()];

        // TODO: non-data packets for entry

        //log::debug!("!!!! decap SRC: {src_addr:?}");

        match self
            .entry_tun
            .decapsulate(src_addr, datagram, &mut horrible_dst)
        {
            TunnResult::Done => TunnResult::Done,
            TunnResult::Err(e) => TunnResult::Err(e),
            TunnResult::WriteToNetwork(packet) => {
                // FIXME: how do we encapsulate the inner part when it's already encapsulated? ...
                // Or is this fine since it's only about handshakes for entry, etc.?

                let new_packet = &mut dst[..packet.len()];
                new_packet.copy_from_slice(&packet);

                TunnResult::WriteToNetwork(new_packet)
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                //log::debug!("!!!!");
                //log::debug!("!!!! exit decap: -> {addr}");
                //log::debug!("!!!!");

                if &addr != self.exit_endpoint.ip() {
                    // TODO: what is correct behavior?
                    let new_packet = &mut dst[..packet.len()];
                    new_packet.copy_from_slice(&packet);
                    return TunnResult::WriteToTunnelV4(new_packet, addr);
                }

                //log::debug!("!!!!");
                //log::debug!("!!!! exit decap packet len: -> {}", packet.len());
                //log::debug!("!!!!");

                // TODO: sanity check IP packet
                let sliced = SlicedPacket::from_ip(packet).unwrap();

                self.exit_tun.decapsulate(src_addr, sliced.payload, dst)
                //let new_packet = &mut dst[..packet.len()];
                //new_packet.copy_from_slice(&packet);
                //TunnResult::WriteToTunnelV4(new_packet, addr)
            }
            TunnResult::WriteToTunnelV6(packet, addr) => {
                // TODO: check addr?
                // TODO: source?
                log::debug!("exit decap v6: -> {addr}");

                // TODO
                //self.exit_tun.decapsulate(src_addr, packet, dst)
                todo!()
            }
        }
    }

    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        self.exit_tun.stats()
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.exit_tun.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        None
    }

    /// Add an additional IP and UDP header.
    /// When the entry hop decapsulates its WireGuard packet, it will forward traffic to the exit
    /// using this header.
    fn add_inner_ip_header<'a>(&self, dst: &'a mut [u8], payload: &[u8]) -> &'a mut [u8] {
        // FIXME: max size
        // FIXME: src: todo: get from peer/tun
        // FIXME: TTL
        // FIXME: IPv6
        let mut cursor = Cursor::new(dst);
        PacketBuilder::ipv4(
            self.tunnel_ip.octets(),
            self.exit_endpoint.ip().octets(),
            30,
        )
        .udp(self.inner_tun_port, self.exit_endpoint.port())
        .write(&mut cursor, payload)
        .unwrap();

        let pos = cursor.position();
        let dst = cursor.into_inner();
        &mut dst[0..pos as usize]
    }
}
