use crate::RecvData;
use std::io::Result;

use crate::async_imports::*;

#[cfg(target_os = "linux")]
mod linux {
    pub(super) use super::super::linux_imports::*;
    pub(super) use std::os::fd::AsFd;
}

#[cfg(target_os = "linux")]
use linux::*;

#[cfg(target_os = "linux")]
pub async fn send_to(
    socket: &UdpSocket, send_buf: &[u8], send_msg_settings: SendMsgCmsgSettings,
) -> Result<usize> {
    loop {
        // Important to use try_io so that Tokio can clear the socket's readiness
        // flag
        let res = socket.try_io(Interest::WRITABLE, || {
            let fd = socket.as_fd();
            send_msg(fd, send_buf, send_msg_settings).map_err(Into::into)
        });

        match res {
            Err(e) if e.kind() == ErrorKind::WouldBlock =>
                socket.writable().await?,
            res => return res,
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn recv_from(
    socket: &UdpSocket, read_buf: &mut [u8], msg_flags: Option<MsgFlags>,
    store_cmsg_settings: &mut RecvMsgCmsgSettings,
) -> Result<RecvData> {
    loop {
        // Important to use try_io so that Tokio can clear the socket's readiness
        // flag
        let res = socket.try_io(Interest::READABLE, || {
            let fd = socket.as_fd();
            recv_msg(
                fd,
                read_buf,
                msg_flags.unwrap_or(MsgFlags::empty()),
                store_cmsg_settings,
            )
            .map_err(Into::into)
        });

        match res {
            Err(e) if e.kind() == ErrorKind::WouldBlock =>
                socket.readable().await?,
            _ => return res,
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn send_to(
    socket: &UdpSocket, client_addr: SocketAddr,
) -> Result<usize> {
    socket.send_to(send_buf, client_addr).await
}

#[cfg(not(target_os = "linux"))]
pub async fn recv_from(
    socket: &UdpSocket, read_buf: &mut [u8],
) -> Result<RecvData> {
    let recv = socket.recv(read_buf).await?;

    Ok(RecvData::from_bytes(bytes))
}
