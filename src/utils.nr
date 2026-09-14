pub(crate) fn get_array_slice<let N: u32, let M: u32>(
    array: [u8; N],
    start: u32,
    end: u32,
) -> [u8; M] {
    assert(end - start <= M);
    let mut slice = [0 as u8; M];
    for i in 0..M {
        if i < end - start {
            slice[i] = array[start + i];
        }
    }
    slice
}
