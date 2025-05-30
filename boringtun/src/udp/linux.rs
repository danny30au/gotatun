use async_trait::async_trait;
use nix::sys::socket::{setsockopt, sockopt, MsgFlags, MultiHeaders, SockaddrIn, SockaddrStorage};
use std::{
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
};
use tokio::io::Interest;

use crate::device::PacketBuf;

use super::UdpTransport;

const MAX_PACKET_COUNT: usize = 100;

#[derive(Default)]
pub struct SendmmsgBuf {
    targets: Vec<Option<SockaddrStorage>>,
}

#[async_trait]
impl UdpTransport for tokio::net::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &[(PacketBuf, SocketAddr)],
    ) -> io::Result<()> {
        let n = packets.len();
        debug_assert!(n <= MAX_PACKET_COUNT);

        //log::info!("send_to_many {n}");

        let fd = self.as_raw_fd();

        buf.targets.clear();
        packets
            .into_iter()
            .map(|(_packet, target)| Some(SockaddrStorage::from(*target)))
            .for_each(|target| buf.targets.push(target));

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

        self.async_io(Interest::WRITABLE, || {
            let mut multiheaders = MultiHeaders::preallocate(packets.len(), None);
            nix::sys::socket::sendmmsg(
                fd,
                &mut multiheaders,
                packets,
                &buf.targets[..],
                &[],
                MsgFlags::MSG_DONTWAIT,
            )?;

            Ok(())
        })
        .await?;

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }

    async fn send_to(&self, packet: &[u8], target: SocketAddr) -> io::Result<()> {
        self.send_to(packet, target).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

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
        self.local_addr()
    }

    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        setsockopt(self, sockopt::Mark, &mark)?;
        Ok(())
    }
}
