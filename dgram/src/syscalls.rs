use std::time::SystemTime;

#[cfg(target_os = "linux")]
mod linux {
    pub(super) use super::super::linux_imports::*;
    pub(super) use std::net::SocketAddr;
    pub(super) use std::os::fd::AsFd;
    pub(super) use std::time::Instant;
}

#[cfg(target_os = "linux")]
use linux::*;

// An instant with the value of zero, since [`Instant`] is backed by a version
// of timespec this allows to extract raw values from an [`Instant`]
#[cfg(target_os = "linux")]
const INSTANT_ZERO: Instant =
    unsafe { std::mem::transmute(std::time::UNIX_EPOCH) };
#[cfg(target_os = "linux")]
pub(crate) type SyscallResult<T> = std::result::Result<T, Errno>;

fn raw_send_to(
    fd: &impl AsFd, send_buf: &[u8], cmsgs: &[ControlMessage],
    msg_flags: MsgFlags, client_addr: Option<SockaddrStorage>,
) -> SyscallResult<usize> {
    let iov = [IoSlice::new(send_buf)];
    let borrowed = fd.as_fd();

    sendmsg(
        borrowed.as_raw_fd(),
        &iov,
        &cmsgs,
        msg_flags,
        client_addr.as_ref(),
    )
}

/// GSO-compatible convenience wrapper for the `sendmsg` syscall.
#[cfg(target_os = "linux")]
pub fn send_msg(
    fd: impl AsFd, send_buf: &[u8], send_msg_cmsg_settings: SendMsgCmsgSettings,
) -> SyscallResult<usize> {
    let SendMsgCmsgSettings {
        ref segment_size,
        tx_time,
        dst,
    } = send_msg_cmsg_settings;

    let raw_time = tx_time
        .map(|t| t.duration_since(INSTANT_ZERO).as_nanos() as u64)
        .unwrap_or(0);

    let mut cmsgs: SmallVec<[ControlMessage; 2]> = SmallVec::new();

    if let Some(ss) = segment_size {
        // Create cmsg for UDP_SEGMENT.
        cmsgs.push(ControlMessage::UdpGsoSegments(ss));
    }

    let now = Instant::now();
    if tx_time.filter(|t| t > &now).is_some() {
        // Create cmsg for TXTIME.
        cmsgs.push(ControlMessage::TxTime(&raw_time));
    }

    let client_addr = dst.map(SockaddrStorage::from);
    raw_send_to(
        &fd.as_fd(),
        send_buf,
        &cmsgs,
        MsgFlags::empty(),
        client_addr,
    )
}

/// Send an arbitrary array of [`ControlMessage`]s to a socket.
#[cfg(target_os = "linux")]
pub fn send_with_cmsgs(
    fd: impl AsFd, send_buf: &[u8], cmsgs: &[ControlMessage],
    dst: Option<SocketAddr>,
) -> SyscallResult<usize> {
    let client_addr = dst.map(SockaddrStorage::from);
    raw_send_to(&fd.as_fd(), send_buf, cmsgs, MsgFlags::empty(), client_addr)
}

/// Receive a message via `recvmsg`. The returned `RecvData` will contain data
/// from supported cmsgs regardless of if the passed [`StoreCmsgSettings`]
/// indicates that we should store the cmsgs.
///
/// # Note
///
/// It is the caller's responsibility to create and clear the cmsg space. `nix`
/// recommends that the space be created via the `cmsg_space!()` macro.
#[cfg(target_os = "linux")]
pub fn recv_msg(
    fd: impl AsFd, read_buf: &mut [u8], msg_flags: MsgFlags,
    handle_cmsg_settings: &mut RecvMsgCmsgSettings,
) -> SyscallResult<RecvData> {
    let RecvMsgCmsgSettings {
        store_cmsgs,
        ref mut cmsg_space,
    } = handle_cmsg_settings;

    cmsg_space.clear();

    let iov_s = &mut [IoSliceMut::new(read_buf)];
    let cmsg_space_len = cmsg_space.len();

    let borrowed = fd.as_fd();
    match recvmsg::<SockaddrStorage>(
        borrowed.as_raw_fd(),
        iov_s,
        Some(cmsg_space),
        msg_flags,
    ) {
        Ok(r) => {
            let bytes = r.bytes;

            let address = match r.address {
                Some(a) => a,
                _ => return Err(Errno::EINVAL),
            };

            let peer_addr = match address.family() {
                Some(AddressFamily::Inet) => Some(
                    SocketAddrV4::from(*address.as_sockaddr_in().unwrap()).into(),
                ),
                Some(AddressFamily::Inet6) => Some(
                    SocketAddrV6::from(*address.as_sockaddr_in6().unwrap())
                        .into(),
                ),
                _ => None,
            };

            let mut recv_data = RecvData::new(peer_addr, bytes, cmsg_space_len);

            for msg in r.cmsgs() {
                match msg {
                    ControlMessageOwned::ScmTimestampns(time) =>
                        recv_data.rx_time =
                            SystemTime::UNIX_EPOCH.checked_add(time.into()),
                    ControlMessageOwned::UdpGroSegments(gro) =>
                        recv_data.gro = Some(gro),
                    ControlMessageOwned::RxqOvfl(c) => {
                        if let Ok(1) = getsockopt(&borrowed, RxqOvfl) {
                            recv_data.metrics = Some(RecvMetrics {
                                udp_packets_dropped: c as u64,
                            });
                        }
                    },
                    _ => return Err(Errno::EINVAL),
                }

                if *store_cmsgs {
                    recv_data.cmsgs.push(msg);
                }
            }

            Ok(recv_data)
        },
        Err(e) => Err(e),
    }
}

fn std_time_to_u64(time: &Instant) -> u64 {
    const NANOS_PER_SEC: u64 = 1_000_000_000;
    const INSTANT_ZERO: std::time::Instant =
        unsafe { std::mem::transmute(std::time::UNIX_EPOCH) };

    let raw_time = time.duration_since(INSTANT_ZERO);

    let sec = raw_time.as_secs();
    let nsec = raw_time.subsec_nanos();

    sec * NANOS_PER_SEC + nsec as u64
}

#[cfg(all(test, target_os = "linux", not(target_os = "android")))]
mod tests {
    use nix::cmsg_space;
    use nix::sys::socket::sockopt::ReceiveTimestampns;
    use nix::sys::socket::sockopt::UdpGroSegment;
    use nix::sys::socket::*;
    use nix::sys::time::TimeVal;
    use std::io::IoSliceMut;
    use std::io::Result;
    use std::os::fd::OwnedFd;
    use std::str::FromStr;

    use super::*;

    const UDP_MAX_GSO_PACKET_SIZE: u16 = 65507;

    fn new_sockets() -> Result<(OwnedFd, OwnedFd)> {
        let recv = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        setsockopt(&recv, ReceiveTimestampns, &true)?;
        setsockopt(&recv, UdpGroSegment, &true)?;
        let localhost = SockaddrIn::from_str("127.0.0.1:0").unwrap();
        bind(recv.as_raw_fd(), &localhost).unwrap();

        let send = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        connect(send.as_raw_fd(), &localhost).unwrap();

        Ok((send, recv))
    }

    fn fd_to_socket_addr(fd: &impl AsRawFd) -> Option<SocketAddr> {
        SocketAddr::from_str(
            &getsockname::<SockaddrStorage>(fd.as_raw_fd())
                .unwrap()
                .to_string(),
        )
        .ok()
    }

    #[test]
    fn send_to_simple() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let send_buf = b"njd";
        let addr = fd_to_socket_addr(&recv);

        send_msg(send, send_buf, SendMsgCmsgSettings {
            segment_size: Some(UDP_MAX_GSO_PACKET_SIZE),
            tx_time: None,
            dst: addr,
        })?;

        let mut buf = [0; 3];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let recv = recvmsg::<()>(
            recv.as_raw_fd(),
            &mut read_buf,
            None,
            MsgFlags::empty(),
        )
        .unwrap();

        assert_eq!(recv.bytes, 3);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn send_to_invalid_tx_time() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = fd_to_socket_addr(&recv);

        let send_buf = b"nyj";
        send_msg(send, send_buf, SendMsgCmsgSettings {
            segment_size: Some(UDP_MAX_GSO_PACKET_SIZE),
            // Invalid because we'll have already passed Instant::now by the time
            // we send the message
            tx_time: Some(Instant::now()),
            dst: addr,
        })?;

        let mut buf = [0; 3];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let recv = recvmsg::<()>(
            recv.as_raw_fd(),
            &mut read_buf,
            None,
            MsgFlags::empty(),
        )
        .unwrap();

        assert_eq!(recv.bytes, 3);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn send_to_multiple_segments() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = fd_to_socket_addr(&recv);

        let send_buf = b"devils";
        send_msg(send, send_buf, SendMsgCmsgSettings {
            segment_size: Some(1),
            tx_time: None,
            dst: addr,
        })?;

        let mut buf = [0; 6];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let mut x = cmsg_space!(u32);
        let recv = recvmsg::<()>(
            recv.as_raw_fd(),
            &mut read_buf,
            Some(&mut x),
            MsgFlags::empty(),
        )
        .unwrap();

        assert_eq!(recv.bytes, 6);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn send_to_control_messages() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = fd_to_socket_addr(&recv);

        let send_buf = b"nyj";

        send_msg(send, send_buf, SendMsgCmsgSettings {
            segment_size: None,
            tx_time: Some(Instant::now() + std::time::Duration::from_secs(5)),
            dst: addr,
        })?;

        let mut buf = [0; 3];
        let mut read_buf = [IoSliceMut::new(&mut buf)];

        let mut cmsg_space = cmsg_space!(TimeVal);
        {
            let recv = recvmsg::<SockaddrStorage>(
                recv.as_raw_fd(),
                &mut read_buf,
                Some(&mut cmsg_space),
                MsgFlags::empty(),
            )
            .unwrap();

            assert_eq!(recv.bytes, 3);
        }

        assert!(!cmsg_space.is_empty());
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn recv_from_simple() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = getsockname::<SockaddrStorage>(recv.as_raw_fd()).unwrap();

        let send_buf = b"jets";
        let iov = [IoSlice::new(send_buf)];
        sendmsg(send.as_raw_fd(), &iov, &[], MsgFlags::empty(), Some(&addr))?;

        let mut read_buf = [0; 4];
        let recv_data = recv_msg(
            recv,
            &mut read_buf,
            MsgFlags::empty(),
            &mut RecvMsgCmsgSettings::default(),
        )?;

        assert_eq!(recv_data.bytes, 4);
        assert_eq!(&read_buf, b"jets");
        assert!(recv_data.cmsgs().is_empty());

        Ok(())
    }

    #[test]
    fn recv_from_cmsgs() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = getsockname::<SockaddrStorage>(recv.as_raw_fd()).unwrap();

        let send_buf = b"jets";
        let iov = [IoSlice::new(send_buf)];
        sendmsg(send.as_raw_fd(), &iov, &[], MsgFlags::empty(), Some(&addr))?;

        let cmsg_space = cmsg_space!(TimeVal);
        let mut store_cmsg_settings = RecvMsgCmsgSettings {
            store_cmsgs: true,
            cmsg_space,
        };

        let mut read_buf = [0; 4];
        let recv_data = recv_msg(
            recv,
            &mut read_buf,
            MsgFlags::empty(),
            &mut store_cmsg_settings,
        )?;

        assert_eq!(recv_data.bytes, 4);
        assert_eq!(&read_buf, b"jets");
        assert!(!recv_data.cmsgs().is_empty());

        Ok(())
    }
}
