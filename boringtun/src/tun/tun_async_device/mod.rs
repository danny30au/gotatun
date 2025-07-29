/// Implementations of [IpSend] and [IpRecv] for the [::tun] crate.
use super::*;
use std::sync::Arc;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod tso;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod virtio;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use tso::try_enable_tso;

impl IpSend for Arc<::tun::AsyncDevice> {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        ::tun::AsyncDevice::send(self, &packet.into_bytes()).await?;
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl IpRecv for Arc<::tun::AsyncDevice> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let mut packet = pool.get();
        let n = ::tun::AsyncDevice::recv(self.as_ref(), &mut packet).await?;
        packet.truncate(n);

        packet
            .try_into_ip()
            .map_err(|e| io::Error::other(e.to_string()))
            .map(std::iter::once)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl IpRecv for Arc<::tun::AsyncDevice> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        use bytes::BytesMut;
        use either::Either;

        // FIXME: pool buffers have a cap of 4096, but we need more
        //let mut packet = pool.get();
        let _ = pool;

        let mut buf = BytesMut::zeroed(usize::from(u16::MAX));
        let n = ::tun::AsyncDevice::recv(self.as_ref(), &mut buf).await?;

        let packet = Packet::from_bytes(buf.split_to(n))
            .try_into_ipvx()
            .map_err(|e| io::Error::other(e.to_string()))?;

        // TODO
        let mtu = 1200;

        // TODO: if segmentation and checksum offload is disabled,
        // we could take a more efficient branch where we do not need to check
        // packet length, and whether it's an IP/TCP packet.
        match packet {
            Either::Left(ipv4_packet) => tso::new_tso_iter_ipv4(ipv4_packet, mtu),
            Either::Right(ipv6_packet) => tso::new_tso_iter_ipv6(ipv6_packet, mtu),
        }
    }
}
