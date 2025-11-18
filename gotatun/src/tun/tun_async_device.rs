// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementations of [IpSend] and [IpRecv] for the [tun] crate.

use tokio::{sync::watch, time::sleep};
use tun::AbstractDevice;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};

use std::{convert::Infallible, io, iter, net::IpAddr, sync::Arc, time::Duration};

/// A kernel virtual network device; a TUN device.
///
/// Implements [IpSend] and [IpRecv].
#[derive(Clone)]
pub struct TunDevice {
    tun: Arc<tun::AsyncDevice>,
    state: Arc<TunDeviceState>,
}

struct TunDeviceState {
    mtu: MtuWatcher,

    /// Task which monitors TUN device MTU. Aborted when dropped.
    _mtu_monitor: Task,
}

impl TunDevice {
    /// Construct from a [tun::AsyncDevice].
    pub fn from_tun_device(tun: tun::AsyncDevice) -> io::Result<Self> {
        if tun.packet_information() {
            return Err(io::Error::other("packet_information is not supported"));
        };

        let mtu = tun.mtu()?;
        let (tx, rx) = watch::channel(mtu);

        let tun = Arc::new(tun);
        let tun_weak = Arc::downgrade(&tun);

        // Poll for changes to the MTU of the TUN device.
        // TODO: use the OS-specific event-driven patterns that exist instead of polling
        let watch_task = async move || -> Option<Infallible> {
            let mut mtu = mtu;
            loop {
                sleep(Duration::from_secs(3)).await;
                let tun = tun_weak.upgrade()?;
                let new = tun.mtu().ok()?;
                if new != mtu {
                    mtu = new;
                    tx.send(mtu).ok()?;
                }
            }
        };

        let mtu_monitor = Task::spawn("tun_mtu_monitor", async move {
            watch_task().await;
        });

        Ok(Self {
            tun,
            state: Arc::new(TunDeviceState {
                mtu: rx.into(),
                _mtu_monitor: mtu_monitor,
            }),
        })
    }
}

impl IpSend for TunDevice {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tun.send(&packet.into_bytes()).await?;
        Ok(())
    }
}

impl IpRecv for TunDevice {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let mut packet = pool.get();
        let n = self.tun.recv(&mut packet).await?;
        packet.truncate(n);
        match packet.try_into_ip() {
            Ok(packet) => {
                let packet = packet.try_into_ipvx().expect("packet is not ipv4/ipv6");
                let (source, dest, len, proto, packet) = match packet {
                    either::Either::Left(ipv4) => (
                        IpAddr::from(ipv4.header.source()),
                        IpAddr::from(ipv4.header.destination()),
                        ipv4.header.total_len,
                        ipv4.header.next_protocol(),
                        ipv4.into(),
                    ),
                    either::Either::Right(ipv6) => (
                        IpAddr::from(ipv6.header.source()),
                        IpAddr::from(ipv6.header.destination()),
                        ipv6.header.payload_length,
                        ipv6.header.next_protocol(),
                        ipv6.into(),
                    ),
                };
                log::warn!("Read from TUN {proto:?} len={len} {source}->{dest}");
                Ok(iter::once(packet))
            }
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.state.mtu.clone()
    }
}
