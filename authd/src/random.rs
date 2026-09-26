#[derive(Debug, PartialEq, Eq)]
pub struct RandomUnavailable;

pub trait RandomSource: Send {
    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), RandomUnavailable>;
}

/// The kernel CSPRNG through getrandom(2) with flags 0, which blocks until the
/// pool is initialized. There is no fallback source.
pub struct KernelRandom;

impl RandomSource for KernelRandom {
    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), RandomUnavailable> {
        fill_with(buffer, |chunk| {
            // SAFETY: the pointer and length describe a live, writable slice.
            let result = unsafe { libc::getrandom(chunk.as_mut_ptr().cast(), chunk.len(), 0) };
            if result < 0 {
                Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
            } else {
                Ok(result as usize)
            }
        })
    }
}

/// Fills the whole buffer: retries on EINTR, continues after partial reads and
/// fails closed on any other error or on a call that makes no progress. On
/// failure the buffer is zeroed so no partial randomness is used.
pub fn fill_with(
    buffer: &mut [u8],
    mut call: impl FnMut(&mut [u8]) -> Result<usize, i32>,
) -> Result<(), RandomUnavailable> {
    let mut filled = 0;
    while filled < buffer.len() {
        let remaining = buffer.len() - filled;
        match call(&mut buffer[filled..]) {
            Ok(count) if count > 0 && count <= remaining => filled += count,
            Err(libc::EINTR) => continue,
            Ok(_) | Err(_) => {
                buffer.fill(0);
                return Err(RandomUnavailable);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_reads_are_continued_until_full() {
        let mut calls = Vec::new();
        let mut buffer = [0u8; 10];
        let mut next = 1u8;
        fill_with(&mut buffer, |chunk| {
            calls.push(chunk.len());
            let count = chunk.len().min(3);
            for byte in &mut chunk[..count] {
                *byte = next;
                next += 1;
            }
            Ok(count)
        })
        .unwrap();
        assert_eq!(calls, [10, 7, 4, 1]);
        assert_eq!(buffer, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn eintr_is_retried() {
        let mut results = vec![Err(libc::EINTR), Err(libc::EINTR), Ok(4)].into_iter();
        let mut buffer = [0u8; 4];
        fill_with(&mut buffer, |chunk| {
            let result = results.next().unwrap();
            if let Ok(count) = result {
                chunk[..count].fill(0xAB);
            }
            result
        })
        .unwrap();
        assert_eq!(buffer, [0xAB; 4]);
        assert!(results.next().is_none());
    }

    #[test]
    fn other_errors_fail_closed_and_zero_the_buffer() {
        for error in [libc::EAGAIN, libc::EFAULT, libc::ENOSYS, libc::EINVAL, 0] {
            let mut first = true;
            let mut buffer = [0u8; 8];
            let result = fill_with(&mut buffer, |chunk| {
                if first {
                    first = false;
                    chunk[..4].fill(0xCD);
                    Ok(4)
                } else {
                    Err(error)
                }
            });
            assert_eq!(result, Err(RandomUnavailable));
            assert_eq!(buffer, [0; 8]);
        }
    }

    #[test]
    fn zero_progress_and_overlong_counts_fail_closed() {
        for count in [0usize, 9] {
            let mut buffer = [0u8; 8];
            assert_eq!(
                fill_with(&mut buffer, |_| Ok(count)),
                Err(RandomUnavailable)
            );
        }
    }

    #[test]
    fn kernel_random_fills_the_buffer() {
        let mut buffer = [0u8; 64];
        KernelRandom.fill(&mut buffer).unwrap();
        assert_ne!(buffer, [0u8; 64]);
    }
}
