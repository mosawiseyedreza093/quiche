// Copyright (C) 2021, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use serde::Deserialize;
use serde::Serialize;

use smallvec::SmallVec;

use super::connectivity::TransportOwner;
use super::PacketHeader;
use crate::Bytes;
use crate::events::DataRecipient;
use crate::events::PathEndpointInfo;
use crate::events::RawInfo;
use crate::events::Token;
use crate::StatelessResetToken;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    Idle,
    Open,
    Closed,

    HalfClosedLocal,
    HalfClosedRemote,
    Ready,
    Send,
    DataSent,
    ResetSent,
    ResetReceived,
    Receive,
    SizeKnown,
    DataRead,
    ResetRead,
    DataReceived,
    Destroyed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSpace {
    TransportError,
    ApplicationError,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    NoError,
    InternalError,
    ConnectionRefused,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIdLimitError,
    ProtocolViolation,
    InvalidToken,
    ApplicationError,
    CryptoBufferExceeded,
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QuicEventType {
    VersionInformation,
    AlpnInformation,

    ParametersSet,
    ParametersRestored,

    UdpDatagramsSent,
    UdpDatagramsReceived,
    UdpDatagramDropped,

    PacketSent,
    PacketReceived,
    PacketDropped,
    PacketBuffered,
    PacketsAcked,

    FramesProcessed,

    StreamStateUpdated,

    StreamDataMoved,
    DatagramDataMoved,
    MigrationStateUpdated,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketSentTrigger {
    RetransmitReordered,
    RetransmitTimeout,
    PtoProbe,
    RetransmitCrypto,
    CcBandwidthProbe,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketReceivedTrigger {
    KeysUnavailable,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketDroppedTrigger {
    InternalError,
    Rejected,
    Unsupported,
    Invalid,
    ConnectionUnknown,
    DecryptionFailure,
    General,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketBufferedTrigger {
    Backpressure,
    KeysUnavailable,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    KeyUpdated,
    KeyDiscarded,
}






#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum AckedRanges {
    Single(Vec<Vec<u64>>),
    Double(Vec<(u64, u64)>),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QuicFrameTypeName {
    Padding,
    Ping,
    Ack,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    ApplicationClose,
    HandshakeDone,
    Datagram,
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "frame_type")]
#[serde(rename_all = "snake_case")]
// Strictly, the qlog spec says that all these frame types have a frame_type
// field. But instead of making that a rust object property, just use serde to
// ensure it goes out on the wire. This means that deserialization of frames
// also works automatically.
pub enum QuicFrame {
    Padding {
        length: Option<u32>,
        payload_length: u32,
    },

    Ping {
        length: Option<u32>,
        payload_length: Option<u32>,
    },

    Ack {
        ack_delay: Option<f32>,
        acked_ranges: Option<AckedRanges>,

        ect1: Option<u64>,
        ect0: Option<u64>,
        ce: Option<u64>,

        length: Option<u32>,
        payload_length: Option<u32>,
    },

    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,

        length: Option<u32>,
        payload_length: Option<u32>,
    },

    StopSending {
        stream_id: u64,
        error_code: u64,

        length: Option<u32>,
        payload_length: Option<u32>,
    },

    Crypto {
        offset: u64,
        length: u64,
    },

    NewToken {
        token: Token,
    },

    Stream {
        stream_id: u64,
        offset: u64,
        length: u64,
        fin: Option<bool>,

        raw: Option<RawInfo>,
    },

    MaxData {
        maximum: u64,
    },

    MaxStreamData {
        stream_id: u64,
        maximum: u64,
    },

    MaxStreams {
        stream_type: StreamType,
        maximum: u64,
    },

    DataBlocked {
        limit: u64,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },

    StreamsBlocked {
        stream_type: StreamType,
        limit: u64,
    },

    NewConnectionId {
        sequence_number: u32,
        retire_prior_to: u32,
        connection_id_length: Option<u8>,
        connection_id: Bytes,
        stateless_reset_token: Option<StatelessResetToken>,
    },

    RetireConnectionId {
        sequence_number: u32,
    },

    PathChallenge {
        data: Option<Bytes>,
    },

    PathResponse {
        data: Option<Bytes>,
    },

    ConnectionClose {
        error_space: Option<ErrorSpace>,
        error_code: Option<u64>,
        error_code_value: Option<u64>,
        reason: Option<String>,

        trigger_frame_type: Option<u64>,
    },

    HandshakeDone,

    Datagram {
        length: u64,

        raw: Option<Bytes>,
    },

    Unknown {
        raw_frame_type: u64,
        frame_type_value: Option<u64>,
        raw: Option<RawInfo>,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PreferredAddress {
    pub ip_v4: String,
    pub ip_v6: String,

    pub port_v4: u16,
    pub port_v6: u16,

    pub connection_id: Bytes,
    pub stateless_reset_token: StatelessResetToken,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AlpnIdentifier {
    pub byte_value: Option<Bytes>,
    pub string_value: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QuicVersionInformation {
    pub server_versions: Option<AlpnIdentifier>,
    pub client_versions: Option<AlpnIdentifier>,
    pub chosen_version: Option<AlpnIdentifier>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AlpnInformation {
    pub server_alpns: Option<Vec<Bytes>>,
    pub client_alpns: Option<Vec<Bytes>>,
    pub chosen_alpn: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ParametersSet {
    pub owner: Option<TransportOwner>,

    pub resumption_allowed: Option<bool>,
    pub early_data_enabled: Option<bool>,
    pub tls_cipher: Option<String>,

    pub original_destination_connection_id: Option<Bytes>,
    pub initial_source_connection_id: Option<Bytes>,
    pub retry_source_connection_id: Option<Bytes>,
    pub stateless_reset_token: Option<StatelessResetToken>,
    pub disable_active_migration: Option<bool>,

    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u32>,
    pub ack_delay_exponent: Option<u16>,
    pub max_ack_delay: Option<u16>,
    pub active_connection_id_limit: Option<u32>,

    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,

    pub preferred_address: Option<PreferredAddress>,

    pub max_datagram_frame_size: Option<u64>,

    pub grease_quic_bit: Option<bool>
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ParametersRestored {
    pub disable_active_migration: Option<bool>,

    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u32>,
    pub active_connection_id_limit: Option<u32>,

    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Ecn {
    #[serde(rename = "Not-ECT")]
    NotEct,
    #[serde(rename = "ECT(1)")]
    Ect1,
    #[serde(rename = "ECT(0)")]
    Ect0,
    #[serde(rename = "CE")]
    CE,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct UdpDatagramsReceived {
    pub count: Option<u16>,
    pub raw: Option<Vec<RawInfo>>,
    pub ecn: Option<Ecn>,
    pub datagram_ids: Option<Vec<u32>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct UdpDatagramsSent {
    pub count: Option<u16>,
    pub raw: Option<Vec<RawInfo>>,
    pub ecn: Option<Ecn>,
    pub datagram_ids: Option<Vec<u32>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct UdpDatagramDropped {
    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PacketReceived {
    pub header: PacketHeader,
    // `frames` is defined here in the QLog schema specification. However,
    // our streaming serializer requires serde to put the object at the end,
    // so we define it there and depend on serde's preserve_order feature.

    pub stateless_reset_token: Option<StatelessResetToken>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub trigger: Option<PacketReceivedTrigger>,

    pub frames: Option<Vec<QuicFrame>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PacketSent {
    pub header: PacketHeader,
    // `frames` is defined here in the QLog schema specification. However,
    // our streaming serializer requires serde to put the object at the end,
    // so we define it there and depend on serde's preserve_order feature.

    pub stateless_reset_token: Option<StatelessResetToken>,

    pub supported_versions: Option<Vec<Bytes>>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,
    pub is_mtu_probe_packet: Option<bool>,

    pub trigger: Option<PacketSentTrigger>,

    pub send_at_time: Option<f32>,

    pub frames: Option<SmallVec<[QuicFrame; 1]>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PacketDropped {
    pub header: Option<PacketHeader>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub details: Option<String>,

    pub trigger: Option<PacketDroppedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PacketBuffered {
    pub header: Option<PacketHeader>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub trigger: Option<PacketBufferedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PacketsAcked {
    pub packet_number_space: Option<PacketNumberSpace>,
    pub packet_numbers: Option<Vec<u64>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct StreamStateUpdated {
    pub stream_id: u64,
    pub stream_type: Option<StreamType>,

    pub old: Option<StreamState>,
    pub new: StreamState,

    pub stream_side: Option<StreamSide>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FramesProcessed {
    pub frames: Vec<QuicFrame>,

    pub packet_numbers: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DataMovedAdditionalInfo {
    FinSet,
    StreamReset,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct StreamDataMoved {
    pub stream_id: Option<u64>,
    pub offset: Option<u64>,
    pub length: Option<u64>,

    pub from: Option<DataRecipient>,
    pub to: Option<DataRecipient>,

    pub additional_info: Option<DataMovedAdditionalInfo>,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DatagramDataMoved {
    pub length: Option<u64>,
    pub from: Option<DataRecipient>,
    pub to: Option<DataRecipient>,
    pub raw: Option<RawInfo>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    ProbingStarted,
    ProbingAbandoned,
    ProbingSuccessful,
    MigrationStarted,
    MigrationAbandoned,
    MigrationComplete,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MigrationStateUpdated {
    pub old: Option<MigrationState>,
    pub new: MigrationState,

    pub path_id: Option<String>,

    pub path_remote: Option<PathEndpointInfo>,
    pub path_local: Option<PathEndpointInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    #[test]
    fn packet_header() {
        let pkt_hdr = make_pkt_hdr(PacketType::Initial);

        let log_string = r#"{
  "packet_type": "initial",
  "packet_number": 0,
  "version": "1",
  "scil": 8,
  "dcil": 8,
  "scid": "7e37e4dcc6682da8",
  "dcid": "36ce104eee50101c"
}"#;

        assert_eq!(serde_json::to_string_pretty(&pkt_hdr).unwrap(), log_string);
    }
}