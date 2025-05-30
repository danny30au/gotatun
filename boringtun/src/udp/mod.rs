use std::{
    io::{self, IoSliceMut},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use linux::VectorizedUdpSocket;
use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrIn};
use tokio::io::Interest;

use crate::device::PacketBuf;

#[cfg(target_os = "linux")]
mod linux;

#[async_trait]
pub trait UdpTransport: Send + Sync {
    fn clone_lol(&self) -> Box<dyn UdpTransport>;

    async fn send_to(&mut self, packets: &[u8], target: SocketAddr) -> io::Result<()>;
    async fn send_many_to(&mut self, packets: &[(PacketBuf, SocketAddr)]) -> io::Result<()> {
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
    async fn recv_vectored(
        &self,
        bufs: &mut [PacketBuf],
        source_addrs: &mut [Option<SocketAddr>],
    ) -> io::Result<usize>;
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
pub trait UdpTransportFactory: Send + Sync {
    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Arc<dyn UdpTransport>, Arc<dyn UdpTransport>)>;
}

pub struct UdpSocketFactory;

#[async_trait]
impl UdpTransport for Arc<tokio::net::UdpSocket> {
    fn clone_lol(&self) -> Box<dyn UdpTransport> {
        Box::new(Arc::clone(self))
    }

    async fn send_to(&mut self, packet: &[u8], target: SocketAddr) -> io::Result<()> {
        tokio::net::UdpSocket::send_to(self, packet, target).await?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn max_number_of_packets_to_recv(&self) -> usize {
        100
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::recv_from(self, buf).await
    }

    /// Returns the number of packets received. 'bufs' and 'source_addrs' receive packets and
    /// the source of each buf, respectively.
    ///
    /// # Arguments
    /// - `bufs` - A slice of buffers that will receive UDP datagrams.
    /// - 'source_addrs' - Source addresses to receive. The length must equal that of 'bufs'.
    async fn recv_vectored(
        &self,
        bufs: &mut [PacketBuf],
        source_addrs: &mut [Option<SocketAddr>],
    ) -> io::Result<usize> {
        debug_assert_eq!(bufs.len(), source_addrs.len());

        use std::os::fd::AsRawFd;
        let fd = self.as_raw_fd();

        let (num_bufs, lens) = self
            .async_io(Interest::READABLE, || {
                let n_packets = bufs.len();
                let mut headers = MultiHeaders::<SockaddrIn>::preallocate(n_packets, None);

                let mut msgs = Vec::with_capacity(n_packets);
                msgs.extend(
                    bufs.iter_mut()
                        .map(|buf| [IoSliceMut::new(&mut buf.buf[..])]),
                );

                let results = nix::sys::socket::recvmmsg(
                    fd,
                    &mut headers,
                    msgs.iter_mut(),
                    MsgFlags::MSG_DONTWAIT,
                    None,
                )?;

                // FIXME :(
                let mut lens = Vec::with_capacity(n_packets);
                for (out_addr, result) in source_addrs.iter_mut().zip(results.into_iter()) {
                    lens.push(result.bytes);
                    *out_addr = result.address.map(|addr| addr.into());
                }
                let num_bufs = lens.len();

                Ok((num_bufs, lens))
            })
            .await?;

        for (buf, len) in bufs.iter_mut().zip(lens) {
            // FIXME :(
            buf.packet_len = len;
        }

        Ok(num_bufs)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        tokio::net::UdpSocket::local_addr(self)
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        use nix::sys::socket::{setsockopt, sockopt};
        setsockopt(&self, sockopt::Mark, &mark)?;
        Ok(())
    }
}

#[async_trait]
impl UdpTransportFactory for UdpSocketFactory {
    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Arc<dyn UdpTransport>, Arc<dyn UdpTransport>)> {
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

        #[cfg(target_os = "linux")]
        let udp_v4 = VectorizedUdpSocket::new(udp_v4);

        #[cfg(target_os = "linux")]
        let udp_v6 = VectorizedUdpSocket::new(udp_v6);

        Ok((Arc::new(udp_v4), Arc::new(udp_v6)))
    }
}
