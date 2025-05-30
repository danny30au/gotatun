use async_trait::async_trait;
use nix::sys::socket::{setsockopt, sockopt, MsgFlags, MultiHeaders, SockaddrStorage};
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd},
    sync::Arc,
};
use tokio::io::Interest;

use crate::device::PacketBuf;

use super::UdpTransport;

const MAX_PACKET_COUNT: usize = 100;

pub struct VectorizedUdpSocket {
    udp_socket: Arc<tokio::net::UdpSocket>,
    targets: Vec<Option<SockaddrStorage>>,
}

impl VectorizedUdpSocket {
    pub fn new(udp_socket: Arc<tokio::net::UdpSocket>) -> Self {
        Self {
            udp_socket,
            targets: Vec::new(),
        }
    }
}

impl Clone for VectorizedUdpSocket {
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.udp_socket))
    }
}

#[async_trait]
impl UdpTransport for VectorizedUdpSocket {
    fn clone_lol(&self) -> Box<dyn UdpTransport> {
        Box::new(self.clone())
    }

    async fn send_many_to(&mut self, packets: &[(PacketBuf, SocketAddr)]) -> io::Result<()> {
        let n = packets.len();
        debug_assert!(n <= MAX_PACKET_COUNT);

        //log::info!("send_to_many {n}");

        let fd = self.udp_socket.as_fd().as_raw_fd();

        self.targets.clear();
        packets
            .into_iter()
            .map(|(_packet, target)| Some(SockaddrStorage::from(*target)))
            .for_each(|target| self.targets.push(target));

        // This allocation can't be put in the struct because of lifetimes.
        // So we allocate it on the stack instead.
        let mut packets_buf = [[IoSlice::new(&[])]; MAX_PACKET_COUNT];
        packets
            .into_iter()
            .map(|(packet_buf, _target)| [IoSlice::new(packet_buf.packet())])
            .enumerate()
            // packets.len() is no greater than MAX_PACKET_COUNT
            .for_each(|(i, packet)| packets_buf[i] = packet);
        let packets = &packets_buf[..n];

        self.udp_socket
            .async_io(Interest::WRITABLE, || {
                let mut multiheaders = MultiHeaders::preallocate(packets.len(), None);
                nix::sys::socket::sendmmsg(
                    fd,
                    &mut multiheaders,
                    packets,
                    &self.targets[..],
                    &[],
                    MsgFlags::empty(),
                )?;

                Ok(())
            })
            .await?;

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }

    async fn send_to(&mut self, packet: &[u8], target: SocketAddr) -> io::Result<()> {
        self.udp_socket.send_to(packet, target).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.udp_socket.recv_from(buf).await
    }

    async fn recv_vectored(
        &self,
        bufs: &mut [PacketBuf],
        source_addrs: &mut [Option<SocketAddr>],
    ) -> io::Result<usize> {
        self.udp_socket.recv_vectored(bufs, source_addrs).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp_socket.local_addr()
    }

    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        setsockopt(&self.udp_socket, sockopt::Mark, &mark)?;
        Ok(())
    }
}
