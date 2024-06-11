use crate::RecvData;
use crate::RecvMsgCmsgSettings;
use crate::SendMsgCmsgSettings;
use std::io::Result;
use std::os::fd::AsFd;

#[cfg(target_os = "linux")]
use super::linux_imports::*;

#[cfg(target_os = "linux")]
pub fn send_to(
    fd: &impl AsFd, send_buf: &[u8], sendmsg_settings: SendMsgCmsgSettings,
) -> Result<usize> {
    let sent = send_msg(fd, send_buf, sendmsg_settings);

    match sent {
        Ok(s) => Ok(s),
        // TODO: propagate or transform?
        Err(Errno::EAGAIN) => Err(std::io::Error::last_os_error()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(target_os = "linux")]
pub fn recv_from(
    fd: &impl AsFd, read_buf: &mut [u8], msg_flags: Option<MsgFlags>,
    store_cmsg_settings: &mut RecvMsgCmsgSettings,
) -> Result<RecvData> {
    let recvd = recv_msg(
        fd,
        read_buf,
        msg_flags.unwrap_or(MsgFlags::empty()),
        store_cmsg_settings,
    );

    match recvd {
        Ok(r) => Ok(r),
        Err(Errno::EAGAIN) => Err(std::io::Error::last_os_error()),
        Err(e) => Err(e.into()),
    }
}

// TODO: these async functions shouldn't be here
#[cfg(not(target_os = "linux"))]
pub async fn send_to(
    socket: &UdpSocket, client_addr: SocketAddr, send_buf: &[u8],
    _segment_size: usize, _num_pkts: usize, _tx_time: Option<Instant>,
) -> Result<usize> {
    socket.send_to(send_buf, client_addr)
}

// Signature changes because we can't use MessageFlags outside of a *NIX context
#[cfg(not(target_os = "linux"))]
pub async fn recv_from(
    socket: &UdpSocket, read_buf: &mut [u8], _cmsg_space: &mut Vec<u8>,
) -> Result<RecvData> {
    let recv = socket.recv(read_buf)?;

    Ok(RecvData {
        bytes: recv,
        peer_addr: None,
        metrics: None,
        gro: None,
        rx_time: None,
    })
}
