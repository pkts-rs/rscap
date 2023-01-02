
/* 
pub fn ones_complement_16bit(bytes: &[u8]) -> u16 {
    todo!()
}
*/

#[inline]
pub(crate) fn to_array<'a, const T: usize>(bytes: &'a [u8], start: usize) -> Option<[u8; T]> {
    Some(*get_array(bytes, start)?)
}

#[inline]
pub(crate) fn get_array<'a, const T: usize>(
    mut bytes: &'a [u8],
    start: usize,
) -> Option<&'a [u8; T]> {
    bytes = bytes.get(start..start + T)?;

    // SAFETY: `bytes` is guaranteed from above to be `T` bytes long.
    // SAFETY: an array reference is made up of just a pointer, which can be retrieved from the bytes slice
    // SAFETY: the lifetime of the resulting array ref will not outlive the slice it was created from
    unsafe { Some(&*(bytes.as_ptr() as *const [_; T])) }
}

#[inline]
pub(crate) fn get_mut_array<'a, const T: usize>(
    mut bytes: &'a mut [u8],
    start: usize,
) -> Option<&'a mut [u8; T]> {
    bytes = bytes.get_mut(start..start + T)?;

    // SAFETY: `bytes` is guaranteed from above to be `T` bytes long.
    // SAFETY: an array reference is made up of just a pointer, which can be retrieved from the bytes slice
    // SAFETY: the lifetime of the resulting array ref will not outlive the slice it was created from
    unsafe { Some(&mut *(bytes.as_mut_ptr() as *mut [_; T])) }
}

#[inline]
pub(crate) fn padded_length<const T: usize>(unpadded_len: usize) -> usize {
    unpadded_len + ((T - (unpadded_len % T)) % T)
}
