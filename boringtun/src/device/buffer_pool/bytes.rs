use std::{collections::VecDeque, mem};

use bytes::BytesMut;

pub struct BufferPool {
    current_buf: BytesMut,
    pool: VecDeque<BytesMut>,
    allocation_len: usize,
}

impl BufferPool {
    pub fn new(allocation_len: usize) -> Self {
        let mut initial_buf = BytesMut::zeroed(allocation_len);

        Self {
            pool: [initial_buf.split_to(0)].into(),
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
    pub fn take(&mut self, len: usize) -> BytesMut {
        let buf = self.ensure_capacity(len);
        buf.split_to(len)
    }

    /// Ensure [Self::current_buf] contains at least len bytes, and borrow it.
    fn ensure_capacity(&mut self, len: usize) -> &mut BytesMut {
        if len > self.allocation_len {
            todo!("how to handle this case?")
        }

        // if current_buf has capacity to spare, split off a chunk and return it.
        if len <= self.current_buf.len() {
            //let buf = self.current_buf.split_off(self.current_buf.len() - len);
            return &mut self.current_buf;
        }

        //self.current_buf.truncate(0);

        // if current_buf is out of capacity, we need to allocate a new buffer or re-use a
        // reclaimed one.
        let mut new_buf = if let Some(mut reclaimed_buf) = self.pool.pop_front() {
            // try to cheaply reclaim bytes in the backing buffer without allocating.
            debug_assert!(reclaimed_buf.is_empty());
            if reclaimed_buf.try_reclaim(self.allocation_len) {
                log::info!("managed to re-use a buffer!");
                reclaimed_buf.resize(self.allocation_len, 0u8);
                reclaimed_buf
            } else {
                // if we failed, the backing buffer is still in use. Put it back in the queue,
                // we'll try again on the next allocation.
                self.pool.push_front(reclaimed_buf);

                self.alloc_new()
            }
        } else {
            log::info!("pool empty");
            self.alloc_new()
        };

        // put the new buffer in the pool to be re-used later when it's empty and unused
        self.pool.push_back(new_buf.split_to(0));

        // set the buffer that was just allocated/reused as `current_buf`
        let _old_buf = mem::replace(&mut self.current_buf, new_buf);

        &mut self.current_buf
    }

    /// Allocate a fresh buffer of [`Self::allocation_len`] capacity.
    fn alloc_new(&self) -> BytesMut {
        log::info!("Allocating new buffer");
        log::info!(
            "Unreclaimed allocations: {} ({}B)",
            self.pool.len(),
            self.pool.len() * self.allocation_len
        );
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
            assert_eq!(&pool.take(s.len())[..], s);
        }
    }
}
