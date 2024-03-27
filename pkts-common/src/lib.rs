


// TODO: make buffer a Buffer<'a> instead?

#[derive(Clone, Debug)]
pub struct Buffer<const N: usize> {
    buf: [u8; N],
    buf_len: usize,
}

impl<const N: usize> Buffer<N> {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.buf_len]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[..self.buf_len]
    }

    /// Appends the provided bytes to the buffer, panicking if insufficient space is available in
    /// the buffer.
    #[inline]
    pub fn append(&mut self, bytes: &[u8]) {
        self.buf[self.buf_len..self.buf_len + bytes.len()].copy_from_slice(bytes);
        self.buf_len += bytes.len();
    }

    #[inline]
    pub fn into_parts(self) -> ([u8; N], usize) {
        (self.buf, self.buf_len)
    }

    /// The length of the stored buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf_len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf_len == 0
    }

    /// The number of unused bytes in the buffer.
    #[inline]
    pub fn remaining(&self) -> usize {
        N - self.buf_len
    }
}

impl<const N: usize> Default for Buffer<N> {
    #[inline]
    fn default() -> Self {
        Self { buf: [0u8; N], buf_len: 0 }
    }
}
