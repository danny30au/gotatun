// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::RwLock;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use std::collections::hash_map::Values;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use crate::device::{AllowedIps, IndexLfsr, peer};
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::packet::{Ip, PacketBuf};
use crate::x25519;

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    allowed_ips: AllowedIps<()>,
    preshared_key: Option<[u8; 32]>,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(AllowedIP { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(AllowedIP { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl Peer {
    pub fn new(
        tunnel: Tunn,
        index: u32,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        preshared_key: Option<[u8; 32]>,
    ) -> Peer {
        Peer {
            tunnel,
            index,
            endpoint: RwLock::new(Endpoint { addr: endpoint }),
            allowed_ips: allowed_ips.iter().map(|ip| (ip, ())).collect(),
            preshared_key,
        }
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.find(addr.into()).is_some()
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = (IpAddr, u8)> + '_ {
        self.allowed_ips.iter().map(|(_, ip, cidr)| (ip, cidr))
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

pub struct SingleDeviceFwd {
    tun_tx_task: JoinHandle<()>,
    tun_rx_task: JoinHandle<()>,
    udp_rx_task: JoinHandle<()>,
    tx_bytes: Arc<AtomicUsize>,
    rx_bytes: Arc<AtomicUsize>,
}

impl SingleDeviceFwd {
    pub fn new(
        tun_device: Arc<::tun::AsyncDevice>,
        endpoint_socket: Arc<tokio::net::UdpSocket>,
        mut single_peer_tun: SinglePeerTun,
    ) -> Self {
        enum PeerMessage {
            HandleOutgoingPacket(BorrowedBuf<PacketBuf>),
            HandleIncomingPacket(IpAddr, BorrowedBuf<PacketBuf>),
        }

        let tx_bytes = Arc::new(AtomicUsize::new(0));
        let rx_bytes = Arc::new(AtomicUsize::new(0));
        let tx_bytes2 = Arc::clone(&tx_bytes);
        let rx_bytes2 = Arc::clone(&rx_bytes);

        let (tun_tx_tx, mut tun_tx_rx): (_, mpsc::Receiver<BorrowedBuf<PacketBuf>>) = mpsc::channel(2000);
        let (udp_tx_tx, mut udp_tx_rx): (_, mpsc::Receiver<BorrowedBuf<PacketBuf>>) = mpsc::channel(2000);

        let (peer_tx, mut peer_rx) = mpsc::channel(2000);
        let udp_tx = endpoint_socket.clone();
        let tun_writer = tun_device.clone();

        let endpoint_addr = single_peer_tun.peer.endpoint().addr.unwrap();

        let peer_tx2 = peer_tx.clone();

        let packet_buffers: PacketPool<PacketBuf> = PacketPool::new(2000);

        let tun_packet_buffers = packet_buffers.clone();
        let tun_rx_task = tokio::spawn(async move {
            loop {
                let mut buf = tun_packet_buffers.get();
                match tun_device.recv(&mut buf.buf[..]).await {
                    Ok(n) => {
                        buf.packet_len = n;
                        peer_tx
                            .send(PeerMessage::HandleOutgoingPacket(buf))
                            .await
                            .expect("Failed to send packet from tun to peer handler");
                    }
                    Err(_err) => {
                        // TODO: Ignore some errors
                        log::error!("Error receiving from tun device: {}", _err);
                        return;
                    }
                }
            }
        });

        let tun_tx_task = tokio::spawn(async move {
            loop {
                match tun_tx_rx.recv().await {
                    Some(buf) => {
                        if let Err(e) = tun_writer.send(buf.packet()).await {
                            log::error!("Error sending packet to network: {}", e);
                        }
                    }
                    None => break,
                }
            }
        });

        let udp_packet_buffers = packet_buffers.clone();
        let udp_rx_task = tokio::spawn(async move {
            loop {
                let mut buf = udp_packet_buffers.get();
                match endpoint_socket.recv_from(&mut buf.buf[..]).await {
                    Ok((n, src_addr)) => {
                        buf.packet_len = n;
                        peer_tx2
                            .send(PeerMessage::HandleIncomingPacket(src_addr.ip(), buf))
                            .await
                            .expect("Failed to send packet from UDP to peer handler");
                    }
                    Err(_err) => {
                        // TODO: Ignore some errors
                        log::error!("Error receiving from endpoint socket: {}", _err);
                        return;
                    }
                }
            }
        });

        let udp_tx_task = tokio::spawn(async move {
            loop {
                match udp_tx_rx.recv().await {
                    Some(buf) => {
                        if let Err(e) = udp_tx.send_to(buf.packet(), endpoint_addr).await {
                            log::error!("Error sending packet to network: {}", e);
                        }
                    }
                    None => break,
                }
            }
        });

        tokio::spawn(async move {
            // Note: All peer tasks are handled in the same task, since they require mutable access
            let mut next_timer_event = Box::pin(tokio::time::sleep(std::time::Duration::from_millis(250)));
            loop {
                let mut dst = packet_buffers.get();

                tokio::select! {
                    peer_message = peer_rx.recv() => {
                        match peer_message {
                            Some(PeerMessage::HandleOutgoingPacket(mut buf)) => {
                                match single_peer_tun.handle_outgoing_packet(buf.packet(), &mut dst.buf[..]) {
                                    TunnResult::WriteToNetwork(packet) => {
                                        buf.copy_from(packet);
                                        if let Err(err) = udp_tx_tx.send(buf).await {
                                            log::error!("Failed: udp_tx_tx.send: {err}");
                                        }
                                    }
                                    // TODO: Handle other cases?
                                    _ => ()
                                }
                            }
                            Some(PeerMessage::HandleIncomingPacket(src_addr, mut buf)) => {
                                match single_peer_tun.handle_incoming_packet(src_addr, buf.packet(), &mut dst.buf[..]) {
                                    TunnResult::WriteToNetwork(packet) => {
                                        buf.copy_from(packet);
                                        if let Err(err) = udp_tx_tx.send(buf).await {
                                            log::error!("Failed: udp_tx_tx.send: {err}");
                                        }

                                        // Flush outgoing packet queue
                                        loop {
                                            match single_peer_tun.peer.tunnel.decapsulate(None, &[], &mut dst.buf[..]) {
                                                TunnResult::WriteToNetwork(packet) => {
                                                    let mut buf = packet_buffers.get();
                                                    buf.copy_from(packet);

                                                    let _ = udp_tx_tx.send(buf).await;
                                                }
                                                TunnResult::Done => break,
                                                TunnResult::Err(_) => continue,
                                                _ => unreachable!("unexpected TunnResult"),
                                            }
                                        }
                                    }
                                    TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                                        buf.copy_from(packet);
                                        if let Err(err) = tun_tx_tx.send(buf).await {
                                            log::error!("Failed: tun_tx_tx.send: {err}");
                                        }
                                    }
                                    // TODO: Handle other cases?
                                    _ => (),
                                }
                            }
                            None => break,
                        }
                    }
                    _ = &mut next_timer_event => {
                        match single_peer_tun.update_timers(&mut dst.buf[..]) {
                            TunnResult::Done => {}
                            TunnResult::Err(WireGuardError::ConnectionExpired) => {}
                            TunnResult::Err(e) => log::error!("Timer error = {e:?}: {e:?}"),
                            TunnResult::WriteToNetwork(packet) => {
                                let mut buf = packet_buffers.get();
                                buf.copy_from(packet);

                                match endpoint_addr {
                                    SocketAddr::V4(_) => udp_tx_tx.send(buf).await.ok(),
                                    SocketAddr::V6(_) => udp_tx_tx.send(buf).await.ok(),
                                };
                            }
                            _ => unreachable!("unexpected result from update_timers"),
                        }

                        // TODO: hacky
                        let (new_tx_bytes, new_rx_bytes) = single_peer_tun.stats();
                        tx_bytes.swap(new_tx_bytes, std::sync::atomic::Ordering::Relaxed);
                        rx_bytes.swap(new_rx_bytes, std::sync::atomic::Ordering::Relaxed);

                        next_timer_event = Box::pin(tokio::time::sleep(std::time::Duration::from_millis(250)));
                    }
                    else => {
                        break;
                    }
                }
            }
        });

        SingleDeviceFwd { tun_tx_task, tun_rx_task, udp_rx_task, tx_bytes: tx_bytes2, rx_bytes: rx_bytes2 }
    }

    pub fn stop(&self) {
        self.udp_rx_task.abort();
        self.tun_rx_task.abort();
        self.tun_tx_task.abort();
    }

    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (usize, usize) {
        (self.tx_bytes.load(std::sync::atomic::Ordering::Relaxed),
         self.rx_bytes.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl Drop for SingleDeviceFwd {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A glorified mpsc channel for reusable packet buffers.
pub struct PacketPool<Buf> {
    tx: mpsc::Sender<Buf>,
    rx: Arc<std::sync::Mutex<mpsc::Receiver<Buf>>>,
}

impl<Buf: Default> PacketPool<Buf> {
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        PacketPool { tx, rx: Arc::new(std::sync::Mutex::new(rx)) }
    }

    /// Retrieve a new buffer.
    ///
    /// If none is available, allocate a new one.
    pub fn get(&self) -> BorrowedBuf<Buf> {
        let mut rx = self.rx.lock().unwrap();
        let inner = rx.try_recv().unwrap_or_else(|_| Buf::default());
        drop(rx);

        BorrowedBuf {
            tx: self.tx.clone(),
            inner: Some(inner),
        }
    }
}

impl<Buf> Clone for PacketPool<Buf> {
    fn clone(&self) -> Self {
        PacketPool {
            tx: self.tx.clone(),
            rx: Arc::clone(&self.rx),
        }
    }
}

/// See [PacketBuffers]. When dropped, the buffer is returned to the pool.
#[derive(Clone)]
pub struct BorrowedBuf<Buf> {
    // wasteful :(
    tx: mpsc::Sender<Buf>,
    inner: Option<Buf>,
}

impl<Buf> BorrowedBuf<Buf> {
    /// Restore packet to the channel for reuse.
    ///
    /// If the channel is already full, this does nothing.
    pub fn free(mut self) {
        self.free_inner();
    }

    fn free_inner(&mut self) {
        let _ = self.tx.try_send(self.inner.take().unwrap());
    }
}

impl<Buf> Deref for BorrowedBuf<Buf> {
    type Target = Buf;

    fn deref(&self) -> &Buf {
        self.inner.as_ref().expect("buf should not be None")
    }
}

impl<Buf> DerefMut for BorrowedBuf<Buf> {
    fn deref_mut(&mut self) -> &mut Buf {
        self.inner.as_mut().expect("buf should not be None")
    }
}

impl<Buf> Drop for BorrowedBuf<Buf> {
    fn drop(&mut self) {
        self.free_inner();
    }
}

/// A single-peer tunnel
pub struct SinglePeerTun {
    peer: Peer,
}

impl SinglePeerTun {
    pub fn new(
        static_secret: x25519::StaticSecret,
        peer_pubkey: x25519::PublicKey,
        peer_endpoint: SocketAddr,
        preshared_key: Option<[u8; 32]>,
        allowed_ips: &[AllowedIP],
    ) -> Self {
        let index = IndexLfsr::random_index();

        let tunn = Tunn::new(
            static_secret,
            peer_pubkey,
            preshared_key,
            None,
            index,
            // TODO: rate limiter
            None,
        );
        let peer = Peer::new(tunn, index, Some(peer_endpoint), allowed_ips, preshared_key);

        SinglePeerTun { peer }
    }

    /// Decrypt an incoming packet
    // TODO: Packet queue must be flushed if this returns a UDP packet
    pub fn handle_incoming_packet<'a>(
        &mut self,
        src_addr: IpAddr,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if !self.peer.is_allowed_ip(src_addr) {
            return TunnResult::Done;
        }
        // TODO: Check index
        self.peer.tunnel.decapsulate(Some(src_addr), src, dst)
    }

    /// Select appropriate peer for and decrypt an incoming packet
    pub fn handle_outgoing_packet<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let Some(dst_addr) = Tunn::dst_address(src) else {
            return TunnResult::Done;
        };
        // Ignore packet if not in allowed IPs
        if !self.peer.is_allowed_ip(dst_addr) {
            return TunnResult::Done;
        }
        self.peer.tunnel.encapsulate(src, dst)
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.peer.update_timers(dst)
    }

    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (usize, usize) {
        let (_last_handshake, tx_bytes, rx_bytes, ..) = self.peer.tunnel.stats();
        (tx_bytes, rx_bytes)
    }
}

/// Handles rx, tx, and rate limiting for a set of peers owned by a device. This does not include
/// any I/O.
///
// TODO: This is actually a "device", but I want to keep I/O out of the picture.
pub struct Peers {
    rate_limiter: Arc<RateLimiter>,
    /// Key pair for the device
    // TODO: pass in?
    key: KeyPair,
    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,
}

pub enum PeersResult<'a> {
    Done,
    /// Send UDP packet
    WriteToNetwork(&'a mut [u8], IpAddr),
    /// Send tunnel packet
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    /// Send tunnel packet
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
    Err(WireGuardError),
}

impl Peers {
    /// Select appropriate peer for and decrypt an incoming packet
    // TODO: Packet queue must be flushed if this returns a UDP packet
    pub async fn handle_incoming_packet<'a>(
        &self,
        src_addr: IpAddr,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> PeersResult<'a> {
        // Process the packet
        let Ok(parsed_packet) = Tunn::parse_incoming_packet(src) else {
            // Ignore any errors
            return PeersResult::Done;
        };

        // TODO: Handle cookies and apply rate limiting. This is broken due to lifetimes
        /*match self.rate_limiter.rate_limit_packet(Some(src_addr), &parsed_packet, dst) {
            Ok(()) => (),
            // Send cookie reply
            Err(TunnResult::WriteToNetwork(cookie_reply)) => return Ok(TunnResult::WriteToNetwork(cookie_reply)),
            // Ignore other errors
            Err(_) => return Ok(TunnResult::Done),
        }*/

        // Identify peer. Handshake initiations are identified by pubkey, and other packet types by
        // receiver index
        let peer = match &parsed_packet {
            Packet::HandshakeInit(p) => {
                parse_handshake_anon(&self.key.private, &self.key.public, p)
                    .ok()
                    .and_then(|hh| {
                        self.peers
                            .get(&x25519::PublicKey::from(hh.peer_static_public))
                    })
            }
            Packet::HandshakeResponse(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketCookieReply(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketData(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
        };

        let Some(peer) = peer else {
            // No matching peer found, ignore packet
            return PeersResult::Done;
        };

        // Process packet with peer's tunnel
        // TODO: Is contention with outgoing task a problem?
        let mut peer = peer.lock().await;
        match peer.tunnel.handle_verified_packet(parsed_packet, dst) {
            TunnResult::Done => return PeersResult::Done,
            // Ignore all errors
            TunnResult::Err(_) => return PeersResult::Done,
            TunnResult::WriteToNetwork(packet) => {
                // FIXME: Flush outgoing packet queue.
                // Maybe this should be done by signaling another task?
                /*loop {
                    match peer.tunnel.decapsulate(None, &[], &mut dst[..]) {
                        TunnResult::WriteToNetwork(packet) => {
                            // TODO: why do we ignore this error?
                            let _ = udp_send_flush.send_to(packet, addr).await;
                        }
                        TunnResult::Done => break,
                        // TODO: why do we ignore this error?
                        TunnResult::Err(_) => continue,

                        // TODO: fix the types so we can't end up here.
                        _ => panic!("unexpected TunnResult"),
                    }
                }*/
                PeersResult::WriteToNetwork(packet, src_addr)
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                if peer.is_allowed_ip(addr) {
                    return PeersResult::WriteToTunnelV4(packet, addr);
                }
                // Drop packets not in allowed IPs
                PeersResult::Done
            }
            TunnResult::WriteToTunnelV6(packet, addr) => {
                if peer.is_allowed_ip(addr) {
                    return PeersResult::WriteToTunnelV6(packet, addr);
                }
                // Drop packets not in allowed IPs
                PeersResult::Done
            }
        }
    }

    /// Select appropriate peer for and encrypt an outgoing packet
    pub async fn handle_outgoing_packet<'a>(
        &self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> PeersResult<'a> {
        let Some(dst_addr) = Tunn::dst_address(src) else {
            return PeersResult::Done;
        };

        // Identify peer by destination address
        let Some(peer) = self.peers_by_ip.find(dst_addr) else {
            // Drop packet if no peer has this in allowed IPs
            return PeersResult::Done;
        };
        let mut peer = peer.lock().await;

        // Encrypt packet using peer's tunnel
        match peer.tunnel.encapsulate(src, dst) {
            // Write packet to network
            TunnResult::WriteToNetwork(packet) => {
                if let Some(addr) = peer.endpoint().addr {
                    PeersResult::WriteToNetwork(packet, addr.ip())
                } else {
                    // No endpoint address, drop packet
                    // TODO: unreachable?
                    PeersResult::Done
                }
            }
            // Packet is queued for later
            TunnResult::Done => PeersResult::Done,
            // Error
            TunnResult::Err(err) => PeersResult::Err(err),
            _ => unreachable!("Unexpected result from encapsulate"),
        }
    }

    /// Return an iterator over pending timers, which should be invoked using `update_timers`.
    /// Timers should be updated periodically every 250 ms.
    pub fn handle_timers<'a>(&'a self) -> PeerIter<'a, impl Iterator<Item = &'a Arc<Mutex<Peer>>>> {
        // TODO: fix rate limiting. only call this once
        /*
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;
        */
        PeerIter::new(self.peers.values())
    }

    // TODO: Function for handling queued packets

    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    pub fn remove_peer(&mut self, pub_key: &x25519::PublicKey) -> Option<Arc<Mutex<Peer>>> {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.blocking_lock();
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            log::info!("Peer removed");

            Some(peer)
        } else {
            None
        }
    }

    /// Update or add peer
    #[allow(clippy::too_many_arguments)]
    pub fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        remove: bool,
        replace_allowed_ips: bool,
        endpoint: Option<SocketAddr>,
        new_allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        if remove {
            // Completely remove a peer
            self.remove_peer(&pub_key);
            return;
        }

        let (index, old_allowed_ips) = if let Some(old_peer) = self.remove_peer(&pub_key) {
            // TODO: Update existing peer?
            let peer = old_peer.blocking_lock();
            let index = peer.index();
            let old_allowed_ips = peer
                .allowed_ips()
                .map(|(addr, cidr)| AllowedIP { addr, cidr })
                .collect();
            drop(peer);

            // TODO: Match pubkey instead of index
            self.peers_by_ip
                .remove(&|p| p.blocking_lock().index() == index);

            (index, old_allowed_ips)
        } else {
            (self.next_index(), vec![])
        };

        // Update an existing peer or add peer
        let tunn = Tunn::new(
            self.key.private().clone(),
            pub_key,
            preshared_key,
            keepalive,
            index,
            None,
        );

        let allowed_ips = if !replace_allowed_ips {
            // append old allowed IPs
            old_allowed_ips
                .into_iter()
                .chain(new_allowed_ips.iter().copied())
                .collect()
        } else {
            new_allowed_ips.to_vec()
        };

        let peer = Peer::new(tunn, index, endpoint, &allowed_ips, preshared_key);
        let peer = Arc::new(Mutex::new(peer));

        self.peers_by_idx.insert(index, Arc::clone(&peer));
        self.peers.insert(pub_key, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in &allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        log::info!("Peer added");
    }
}

struct KeyPair {
    private: x25519::StaticSecret,
    public: x25519::PublicKey,
}

impl KeyPair {
    fn new(private: x25519::StaticSecret) -> Self {
        let public = x25519::PublicKey::from(&private);
        KeyPair { private, public }
    }

    fn public(&self) -> &x25519::PublicKey {
        &self.public
    }

    fn private(&self) -> &x25519::StaticSecret {
        &self.private
    }
}

pub struct PeerIter<'a, It> {
    peers: It,
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a, It: Iterator<Item = &'a Arc<Mutex<Peer>>>> PeerIter<'a, It> {
    fn new(peers: It) -> Self {
        PeerIter {
            peers,
            _phantom: std::marker::PhantomData,
        }
    }

    #[must_use]
    pub async fn update_timers(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let Some(peer) = self.peers.next() else {
            return TunnResult::Done;
        };
        let mut p = peer.lock().await;

        let Some(endpoint_addr) = p.endpoint().addr else {
            // Give up if we have no endpoint address
            return TunnResult::Done;
        };

        match p.update_timers(dst) {
            TunnResult::Done => TunnResult::Done,
            TunnResult::Err(WireGuardError::ConnectionExpired) => TunnResult::Done,
            TunnResult::Err(e) => {
                log::error!("Timer error = {e:?}: {e:?}");
                TunnResult::Done
            }
            // TODO: also return endpoint address
            result @ TunnResult::WriteToNetwork(_) => result,
            _ => unreachable!("unexpected result from update_timers"),
        }
    }
}
