//! Kernel rtnetlink notifications, used only as an invalidation trigger.
//! Message contents are never parsed: Session1 remains the only source of
//! network truth.
use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use tokio::io::{unix::AsyncFd, Interest};

const GROUPS: u32 = (libc::RTMGRP_LINK
    | libc::RTMGRP_IPV4_IFADDR
    | libc::RTMGRP_IPV6_IFADDR
    | libc::RTMGRP_IPV4_ROUTE
    | libc::RTMGRP_IPV6_ROUTE) as u32;

pub struct Netlink {
    socket: AsyncFd<OwnedFd>,
}

impl Netlink {
    /// A NETLINK_ROUTE socket bound to the link, address and route multicast
    /// groups. Unprivileged; nothing is ever sent on it.
    pub fn open() -> io::Result<Self> {
        // SAFETY: plain socket(2) call; the result is checked before use.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a freshly created descriptor owned by nothing else.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: sockaddr_nl is plain data; zeroed is a valid initial value.
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        address.nl_groups = GROUPS;
        // SAFETY: address is a valid sockaddr_nl of the stated length.
        let bound = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            socket: AsyncFd::with_interest(socket, Interest::READABLE)?,
        })
    }

    /// Waits for at least one notification (or a receive-buffer overrun,
    /// which means notifications were lost), then drains the socket.
    pub async fn changed(&self) -> io::Result<()> {
        loop {
            let mut ready = self.socket.readable().await?;
            let mut notified = false;
            let mut buffer = [0u8; 16 * 1024];
            loop {
                // SAFETY: buffer is live and writable for its full length.
                let received = unsafe {
                    libc::recv(
                        self.socket.as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if received > 0 {
                    notified = true;
                    continue;
                }
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EAGAIN) => {
                        ready.clear_ready();
                        break;
                    }
                    Some(libc::ENOBUFS) => notified = true,
                    Some(libc::EINTR) => {}
                    _ if received == 0 => {
                        ready.clear_ready();
                        break;
                    }
                    _ => return Err(error),
                }
            }
            if notified {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_rtnetlink_socket_opens_without_privileges() {
        let netlink = Netlink::open().unwrap();
        // Nothing has changed, so no notification is pending.
        let waited =
            tokio::time::timeout(std::time::Duration::from_millis(50), netlink.changed()).await;
        assert!(waited.is_err());
    }
}
