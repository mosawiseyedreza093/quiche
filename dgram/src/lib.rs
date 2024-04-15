pub mod socket_setup;
pub mod sync;
mod syscalls;
#[cfg(feature = "async")]
pub mod tokio;

use std::net::SocketAddr;
use std::time::Instant;
use std::time::SystemTime;

use nix::sys::socket::ControlMessageOwned;

#[cfg(target_os = "linux")]
#[derive(Default, Copy, Clone)]
pub struct SendMsgCmsgSettings {
    /// Segment sized used in a UDP_SEGMENT message
    pub segment_size: Option<u16>,
    /// Send time used in a TX_TIME message
    pub tx_time: Option<Instant>,
    /// Destination socket address
    pub dst: Option<SocketAddr>,
}

/// Settings for handling control messages when receiving data.
#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct RecvMsgCmsgSettings {
    store_cmsgs: bool,
    cmsg_space: Vec<u8>,
}

/// Output of a `recvmsg` call.
#[derive(Debug, Default)]
pub struct RecvData {
    /// The number of bytes which `recvmsg` returned.
    pub bytes: usize,
    /// The peer address for this message.
    pub peer_addr: Option<SocketAddr>,
    /// Metrics for this `recvmsg` call.
    ///
    /// If no valid metrics exist - for example, when the RXQOVFL sockopt is not
    /// set - this will be `None`.
    pub metrics: Option<RecvMetrics>,
    /// The `UDP_GRO_SEGMENTS` control message data from the result of
    /// `recvmsg`, if it exist.
    pub gro: Option<u16>,
    /// The RX_TIME control message data from the result of `recvmsg`, if it
    /// exists.
    pub rx_time: Option<SystemTime>,
    cmsgs: Vec<ControlMessageOwned>,
}

impl RecvData {
    pub fn new(
        peer_addr: Option<SocketAddr>, bytes: usize, cmsg_space_len: usize,
    ) -> Self {
        Self {
            peer_addr,
            bytes,
            metrics: None,
            gro: None,
            rx_time: None,
            cmsgs: Vec::with_capacity(cmsg_space_len),
        }
    }

    pub fn from_bytes(bytes: usize) -> Self {
        Self {
            bytes,
            ..Default::default()
        }
    }

    /// Returns the list of cmsgs which were returned from calling `recvmsg`. If
    /// `recvmsg` was called with its [`RecvMsgCmsgSettings::store_cmsgs`]
    /// field set to to `false`, this will return an empty slice.
    pub fn cmsgs(&self) -> &[ControlMessageOwned] {
        &self.cmsgs
    }
}

/// Metrics for `recvmsg` calls.
#[derive(Debug, Default)]
pub struct RecvMetrics {
    /// The number of packets dropped between the last received packet and this
    /// one.
    ///
    /// See SO_RXQOVFL for more.
    pub udp_packets_dropped: u64,
}

#[cfg(target_os = "linux")]
mod linux_imports {
    pub(super) use crate::syscalls::recv_msg;
    pub(super) use crate::syscalls::send_msg;
    pub(super) use crate::RecvData;
    pub(super) use crate::RecvMetrics;
    pub(super) use crate::RecvMsgCmsgSettings;
    pub(super) use crate::SendMsgCmsgSettings;
    pub(super) use nix::errno::Errno;
    pub(super) use nix::sys::socket::getsockopt;
    pub(super) use nix::sys::socket::recvmsg;
    pub(super) use nix::sys::socket::sendmsg;
    pub(super) use nix::sys::socket::setsockopt;
    pub(super) use nix::sys::socket::sockopt::ReceiveTimestampns;
    pub(super) use nix::sys::socket::sockopt::RxqOvfl;
    pub(super) use nix::sys::socket::sockopt::TxTime;
    pub(super) use nix::sys::socket::sockopt::UdpGroSegment;
    pub(super) use nix::sys::socket::sockopt::UdpGsoSegment;
    pub(super) use nix::sys::socket::AddressFamily;
    pub(super) use nix::sys::socket::ControlMessage;
    pub(super) use nix::sys::socket::ControlMessageOwned;
    pub(super) use nix::sys::socket::MsgFlags;
    pub(super) use nix::sys::socket::SetSockOpt;
    pub(super) use nix::sys::socket::SockaddrLike;
    pub(super) use nix::sys::socket::SockaddrStorage;
    pub(super) use smallvec::SmallVec;
    pub(super) use std::io::IoSlice;
    pub(super) use std::io::IoSliceMut;
    pub(super) use std::net::SocketAddrV4;
    pub(super) use std::net::SocketAddrV6;
    pub(super) use std::os::fd::AsRawFd;
}

#[cfg(feature = "async")]
mod async_imports {
    pub(super) use std::io::ErrorKind;
    pub(super) use tokio::io::Interest;
    pub(super) use tokio::net::UdpSocket;
}
