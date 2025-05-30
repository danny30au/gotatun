use std::mem;

use bytes::BytesMut;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

pub struct BufferPool {
    current_buf: BytesMut,
    drop_tx: UnboundedSender<BytesMut>,
    drop_rx: UnboundedReceiver<BytesMut>,
    allocation_len: usize,
}

pub struct PacketBuf {
    pub packet: BytesMut,

    allocation_len: usize,

    /// Channel used to return the buffer to the original [BufferPool] when it can be reclaimed.
    drop_tx: UnboundedSender<BytesMut>,
}

impl PacketBuf {
    pub fn packet(&self) -> &[u8] {
        &self.packet[..]
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        let mut buffer = mem::take(&mut self.packet);

        // Check if our `BytesMut` is the sole reference to the backing buffer by trying to reclaim
        // the entire backing buffer.
        buffer.clear();
        if buffer.try_reclaim(self.allocation_len) {
            let _ = self.drop_tx.send(buffer);
        }
    }
}

impl BufferPool {
    pub fn new(allocation_len: usize) -> Self {
        let initial_buf = BytesMut::zeroed(allocation_len);

        let (drop_tx, drop_rx) = mpsc::unbounded_channel();

        Self {
            drop_tx,
            drop_rx,
            current_buf: initial_buf,
            allocation_len,
        }
    }

    /// Borrow a mutable buffer of `len` bytes.
    ///
    /// A subsequent call to [Self::take] with a `len` value no bigger than this one, will return
    /// an owned buffer containing any butes written to this borrow.
    pub fn borrow_mut(&mut self, len: usize) -> &mut [u8] {
        &mut self.ensure_capacity(len)[..]
    }

    /// Get a buffer of `len` bytes.
    pub fn take(&mut self, len: usize) -> PacketBuf {
        let buf = self.ensure_capacity(len);
        let buf = buf.split_to(len);
        PacketBuf {
            packet: buf,
            allocation_len: self.allocation_len,
            drop_tx: self.drop_tx.clone(),
        }
    }

    /// Copy `bytes` into a new owned [PacketBuf].
    pub fn copy(&mut self, bytes: &[u8]) -> PacketBuf {
        let mut buf = self.take(bytes.len());
        buf.packet.copy_from_slice(bytes);
        buf
    }

    /// Ensure [Self::current_buf] contains at least len bytes, and borrow it.
    fn ensure_capacity(&mut self, len: usize) -> &mut BytesMut {
        if len > self.allocation_len {
            todo!("how to handle this case?")
        }

        if len <= self.current_buf.len() {
            return &mut self.current_buf;
        }

        // self.current_buf.clear();

        // if current_buf is out of capacity, we need to allocate a new buffer or re-use a
        // reclaimed one.
        let new_buf = if let Ok(mut reclaimed_buf) = self.drop_rx.try_recv() {
            // try to cheaply reclaim bytes in the backing buffer without allocating.
            debug_assert!(reclaimed_buf.capacity() >= self.allocation_len);
            reclaimed_buf.resize(self.allocation_len, 0u8);
            reclaimed_buf
        } else {
            log::info!("pool empty");
            self.alloc_new()
        };

        // set the buffer that was just allocated/reused as `current_buf`
        self.current_buf = new_buf;

        &mut self.current_buf
    }

    /// Allocate a fresh buffer of [`Self::allocation_len`] capacity.
    fn alloc_new(&self) -> BytesMut {
        log::info!("Allocating new buffer");
        //log::info!(
        //    "Unreclaimed allocations: {} ({}B)",
        //    self.pool.len(),
        //    self.pool.len() * self.allocation_len
        //);
        BytesMut::zeroed(self.allocation_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrow_then_take() {
        let mut pool = BufferPool::new(128);
        let s = b"hello there!";
        for _ in 0..64 {
            pool.borrow_mut(64)[..s.len()].copy_from_slice(s);
            assert_eq!(&pool.take(s.len()).packet[..], s);
        }
    }
}
