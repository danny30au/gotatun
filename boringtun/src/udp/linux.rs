use bytes::BytesMut;
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
use nix::{
    cmsg_space,
    sys::socket::{ControlMessageOwned, MsgFlags, MultiHeaders, SockaddrIn, SockaddrStorage},
};
use std::{
    collections::VecDeque,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
};
use tokio::io::Interest;

use crate::{
    packet::Packet,
    udp::{UdpRecv, UdpSend},
};

use super::UdpTransport;

const MAX_PACKET_COUNT: usize = 100;
const MAX_SEGMENTS: usize = 100;
const MAX_SEGMENT_SIZE: usize = 4096;

#[derive(Default)]
pub struct SendmmsgBuf {
    targets: Vec<Option<SockaddrStorage>>,
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        tokio::net::UdpSocket::send_to(&self.inner, &packet, target).await?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let n = packets.len();
        debug_assert!(n <= MAX_PACKET_COUNT);

        let fd = self.inner.as_raw_fd();

        buf.targets.clear();
        packets
            .iter()
            .map(|(_packet, target)| Some(SockaddrStorage::from(*target)))
            .for_each(|target| buf.targets.push(target));

        // This allocation can't be put in the struct because of lifetimes.
        // So we allocate it on the stack instead.
        let mut packets_buf = [[IoSlice::new(&[])]; MAX_PACKET_COUNT];
        packets
            .iter()
            .map(|(packet, _target)| [IoSlice::new(&packet[..])])
            .enumerate()
            // packets.len() is no greater than MAX_PACKET_COUNT
            .for_each(|(i, packet)| packets_buf[i] = packet);
        let pkts = &packets_buf[..n];

        self.inner
            .async_io(Interest::WRITABLE, || {
                let mut multiheaders = MultiHeaders::preallocate(pkts.len(), None);
                nix::sys::socket::sendmmsg(
                    fd,
                    &mut multiheaders,
                    pkts,
                    &buf.targets[..],
                    [],
                    MsgFlags::MSG_DONTWAIT,
                )?;

                Ok(())
            })
            .await?;

        packets.clear();

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }
}

pub struct RecvManyBuf {
    gro_splits: Vec<BytesMut>,
}

// SAFETY: MultiHeaders contains pointers, but we only ever mutate data in [Self::recv_many_from].
// This should be fine.
unsafe impl Send for RecvManyBuf {}

impl Default for RecvManyBuf {
    fn default() -> Self {
        // TODO: no copy?
        let mut gro_buf = BytesMut::zeroed(MAX_PACKET_COUNT * MAX_SEGMENTS * MAX_SEGMENT_SIZE);
        let mut gro_splits = vec![];
        for _ in 0..MAX_PACKET_COUNT {
            gro_splits.push(gro_buf.split_to(MAX_SEGMENTS * MAX_SEGMENT_SIZE));
        }

        Self { gro_splits }
    }
}

impl UdpRecv for super::UdpSocket {
    type RecvManyBuf = RecvManyBuf;

    fn max_number_of_packets_to_recv(&self) -> usize {
        MAX_SEGMENTS * MAX_PACKET_COUNT
    }

    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::recv_from(&self.inner, buf).await
    }

    async fn recv_many_from(
        &mut self,
        recv_many_bufs: &mut Self::RecvManyBuf,
        bufs: &mut VecDeque<Packet>,
        source_addrs: &mut [Option<SocketAddr>],
    ) -> io::Result<usize> {
        debug_assert_eq!(bufs.len(), source_addrs.len());

        let fd = self.inner.as_raw_fd();

        let num_bufs = self
            .inner
            .async_io(Interest::READABLE, move || {
                // TODO: the CMSG space cannot be reused, so we must allocate new headers each time
                // [ControlMessageOwned::UdpGroSegments(i32)] contains the size of all smaller packets/segments
                let headers = &mut MultiHeaders::<SockaddrIn>::preallocate(
                    MAX_PACKET_COUNT,
                    Some(cmsg_space!(i32)),
                );

                let mut io_slices: [[IoSliceMut; 1]; MAX_PACKET_COUNT] =
                    std::array::from_fn(|_| [IoSliceMut::new(&mut [])]);

                for (i, buf) in recv_many_bufs.gro_splits.iter_mut().enumerate() {
                    io_slices[i] = [IoSliceMut::new(&mut buf[..])];
                }

                let results = nix::sys::socket::recvmmsg(
                    fd,
                    headers,
                    //&mut io_slices[..num_packets],
                    &mut io_slices[..MAX_PACKET_COUNT],
                    MsgFlags::MSG_DONTWAIT,
                    None,
                )?;

                let mut bufs_index = 0;

                for result in results {
                    let iov = result.iovs().next().unwrap();

                    let mut cmsgs = result.cmsgs().unwrap();

                    if let Some(ControlMessageOwned::UdpGroSegments(gro_size)) = cmsgs.next()
                        && gro_size > 0
                    {
                        // Divide packet into GRO-sized segments
                        let gro_size = gro_size as usize;

                        // Number of individual UDP datagrams in this buffer
                        let packet_count = (result.bytes + gro_size - 1) / gro_size;

                        // Segment the buffers into individual packets
                        let mut iov_offset = 0;
                        for _ in 0..(packet_count - 1) {
                            bufs[bufs_index][..gro_size]
                                .copy_from_slice(&iov[iov_offset..iov_offset + gro_size]);
                            bufs[bufs_index].truncate(gro_size);

                            iov_offset += gro_size;

                            source_addrs[bufs_index] = result.address.map(|addr| addr.into());
                            bufs_index += 1;
                        }

                        // Add last packet. It can be smaller than previous segments
                        let mut remaining_bytes = result.bytes % gro_size;
                        if remaining_bytes == 0 {
                            remaining_bytes = gro_size;
                        }
                        bufs[bufs_index][..remaining_bytes]
                            .copy_from_slice(&iov[iov_offset..iov_offset + remaining_bytes]);
                        bufs[bufs_index].truncate(remaining_bytes);

                        source_addrs[bufs_index] = result.address.map(|addr| addr.into());
                        bufs_index += 1;
                    } else {
                        // Single packet
                        source_addrs[bufs_index] = result.address.map(|addr| addr.into());

                        let size = result.bytes;
                        bufs[bufs_index][..size].copy_from_slice(&iov[..size]);
                        bufs[bufs_index].truncate(size);

                        bufs_index += 1;
                    }
                }

                Ok(bufs_index)
            })
            .await?;

        Ok(num_bufs)
    }
}

impl UdpTransport for super::UdpSocket {
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        super::UdpSocket::local_addr(self).map(Some)
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        setsockopt(&self.inner, sockopt::Mark, &mark)?;
        Ok(())
    }
}
