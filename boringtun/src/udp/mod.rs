use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;

use crate::buffer::PacketBuf;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(target_os = "linux"))]
mod generic;

#[async_trait]
pub trait UdpTransport: Send + Sync {
    type SendManyBuf: Default + Send + Sync;

    async fn send_to(&self, packets: &[u8], target: SocketAddr) -> io::Result<()>;
    async fn send_many_to(
        &self,
        _bufs: &mut Self::SendManyBuf,
        packets: &[(PacketBuf, SocketAddr)],
    ) -> io::Result<()> {
        for (packet, target) in packets {
            self.send_to(packet.packet(), *target).await?;
        }
        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        1
    }

    fn max_number_of_packets_to_recv(&self) -> usize {
        1
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    //async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Returns the number of packets received. 'bufs' and 'source_addrs' receive packets and
    /// the source of each buf, respectively.
    ///
    /// # Arguments
    /// - `bufs` - A slice of buffers that will receive UDP datagrams.
    /// - 'source_addrs' - Source addresses to receive. The length must equal that of 'bufs'.
    async fn recv_vectored(
        &self,
        _bufs: &mut [PacketBuf],
        _source_addrs: &mut [Option<SocketAddr>],
    ) -> io::Result<usize> {
        todo!("implement using recv_from")
    }
    fn local_addr(&self) -> io::Result<SocketAddr>;
    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()>;
}

pub struct UdpTransportFactoryParams {
    pub addr_v4: Ipv4Addr,
    pub addr_v6: Ipv6Addr,
    pub port: u16,

    #[cfg(target_os = "linux")]
    pub fwmark: Option<u32>,
}

#[async_trait]
pub trait UdpTransportFactory: Send + Sync + 'static {
    type Transport: UdpTransport + 'static;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Arc<Self::Transport>, Arc<Self::Transport>)>;
}

pub struct UdpSocketFactory;

#[async_trait]
impl UdpTransportFactory for UdpSocketFactory {
    type Transport = tokio::net::UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Arc<Self::Transport>, Arc<Self::Transport>)> {
        fn bind(addr: SocketAddr) -> io::Result<Arc<tokio::net::UdpSocket>> {
            let domain = match addr {
                SocketAddr::V4(..) => socket2::Domain::IPV4,
                SocketAddr::V6(..) => socket2::Domain::IPV6,
            };

            // Construct the socket using `socket2` because we need to set the reuse_address flag.
            let udp_sock =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            udp_sock.set_nonblocking(true)?;
            udp_sock.set_reuse_address(true)?;
            udp_sock.bind(&addr.into())?;

            tokio::net::UdpSocket::from_std(udp_sock.into()).map(Arc::new)
        }

        let mut port = params.port;
        let udp_v4 = bind((params.addr_v4, port).into())?;
        if port == 0 {
            // The socket is using a random port, copy it so we can re-use it for IPv6.
            port = udp_v4.local_addr()?.port();
        }

        let udp_v6 = bind((params.addr_v6, port).into())?;

        #[cfg(target_os = "linux")]
        if let Some(mark) = params.fwmark {
            udp_v4.set_fwmark(mark)?;
            udp_v6.set_fwmark(mark)?;
        }

        Ok((udp_v4, udp_v6))
    }
}
