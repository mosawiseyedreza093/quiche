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

use crate::Bytes;
use crate::Token;
use http::h3::*;
use http::h3;
use quic::connectivity;
use quic::connectivity::*;
use quic::quic::*;
use quic::recovery::*;
use quic::recovery;
use quic::security;

use serde::Deserialize;
use serde::Serialize;

use std::collections::BTreeMap;

pub type ExData = BTreeMap<String, serde_json::Value>;

pub const LOGLEVEL_URI: &str = "urn:ietf:params:qlog:events:gen#loglevel-09";

pub const CONNECTIVITY_URI: &str = "urn:ietf:params:qlog:events:quic#connectivity-08";
pub const SECURITY_URI: &str = "urn:ietf:params:qlog:events:quic#security-08";
pub const QUIC_URI: &str = "urn:ietf:params:qlog:events:quic#quic-08";
pub const RECOVERY_URI: &str = "urn:ietf:params:qlog:events:quic#recovery-08";

pub const H3_URI: &str = "urn:ietf:params:qlog:events:http#h3-08";

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(untagged)]
pub enum EventType {
    ConnectivityEventType(ConnectivityEventType),

    QuicEventType(QuicEventType),

    SecurityEventType(SecurityEventType),

    RecoveryEventType(RecoveryEventType),

    Http3EventType(Http3EventType),

    LogLevelEventType(LogLevelEventType),

    #[default]
    None,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum TimeFormat {
    Absolute,
    Delta,
    Relative,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    pub time: f32,

    // Strictly, the qlog 02 spec says we should have a name field in the
    // `Event` structure. However, serde's autogenerated Deserialize code
    // struggles to read Events properly because the `EventData` types often
    // alias. In order to work around that, we use can use a trick that will
    // give serde autogen all the information that it needs while also produced
    // a legal qlog. Specifically, strongly linking an EventData enum variant
    // with the wire-format name.
    //
    // The trick is to use Adjacent Tagging
    // (https://serde.rs/enum-representations.html#adjacently-tagged) with
    // Struct flattening (https://serde.rs/attr-flatten.html). At a high level
    // this first creates an `EventData` JSON object:
    //
    // {name: <enum variant name>, data: enum variant data }
    //
    // and then flattens those fields into the `Event` object.
    #[serde(flatten)]
    pub data: EventData,

    #[serde(flatten)]
    pub ex_data: ExData,

    pub protocol_type: Option<String>,
    pub group_id: Option<String>,

    pub time_format: Option<TimeFormat>,

    #[serde(skip)]
    ty: EventType,
}

impl Event {
    /// Returns a new `Event` object with the provided time and data.
    pub fn with_time(time: f32, data: EventData) -> Self {
        Self::with_time_ex(time, data, Default::default())
    }

    /// Returns a new `Event` object with the provided time, data and ex_data.
    pub fn with_time_ex(time: f32, data: EventData, ex_data: ExData) -> Self {
        let ty = EventType::from(&data);
        Event {
            time,
            data,
            ex_data,
            protocol_type: Default::default(),
            group_id: Default::default(),
            time_format: Default::default(),
            ty,
        }
    }
}

impl Eventable for Event {
    fn importance(&self) -> EventImportance {
        self.ty.into()
    }

    fn set_time(&mut self, time: f32) {
        self.time = time;
    }
}

impl PartialEq for Event {
    // custom comparison to skip over the `ty` field
    fn eq(&self, other: &Event) -> bool {
        self.time == other.time &&
            self.data == other.data &&
            self.ex_data == other.ex_data &&
            self.protocol_type == other.protocol_type &&
            self.group_id == other.group_id &&
            self.time_format == other.time_format
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JsonEvent {
    pub time: f32,

    #[serde(skip)]
    pub importance: EventImportance,

    pub name: String,
    pub data: serde_json::Value,
}

impl Eventable for JsonEvent {
    fn importance(&self) -> EventImportance {
        self.importance
    }

    fn set_time(&mut self, time: f32) {
        self.time = time;
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum EventImportance {
    #[default]
    Core,
    Base,
    Extra,
}

impl EventImportance {
    /// Returns true if this importance level is included by `other`.
    pub fn is_contained_in(&self, other: &EventImportance) -> bool {
        match (other, self) {
            (EventImportance::Core, EventImportance::Core) => true,

            (EventImportance::Base, EventImportance::Core) |
            (EventImportance::Base, EventImportance::Base) => true,

            (EventImportance::Extra, EventImportance::Core) |
            (EventImportance::Extra, EventImportance::Base) |
            (EventImportance::Extra, EventImportance::Extra) => true,

            (..) => false,
        }
    }
}

impl From<EventType> for EventImportance {
    fn from(ty: EventType) -> Self {
        match ty {
            EventType::ConnectivityEventType(
                ConnectivityEventType::ServerListening,
            ) => EventImportance::Extra,
            EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionStarted,
            ) => EventImportance::Base,
            EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionClosed,
            ) => EventImportance::Base,
            EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionIdUpdated,
            ) => EventImportance::Base,
            EventType::ConnectivityEventType(
                ConnectivityEventType::SpinBitUpdated,
            ) => EventImportance::Base,
            EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionStateUpdated,
            ) => EventImportance::Base,
            EventType::ConnectivityEventType(
                ConnectivityEventType::PathAssigned,
            ) => EventImportance::Extra,
            EventType::ConnectivityEventType(
                ConnectivityEventType::MtuUpdated,
            ) => EventImportance::Extra,

            EventType::SecurityEventType(SecurityEventType::KeyUpdated) =>
                EventImportance::Base,
            EventType::SecurityEventType(SecurityEventType::KeyDiscarded) =>
                EventImportance::Base,

            EventType::QuicEventType(
                QuicEventType::VersionInformation,
            ) => EventImportance::Core,
            EventType::QuicEventType(
                QuicEventType::AlpnInformation,
            ) => EventImportance::Core,
            EventType::QuicEventType(QuicEventType::ParametersSet) =>
                EventImportance::Core,
            EventType::QuicEventType(
                QuicEventType::ParametersRestored,
            ) => EventImportance::Base,
            EventType::QuicEventType(
                QuicEventType::UdpDatagramsReceived,
            ) => EventImportance::Extra,
            EventType::QuicEventType(QuicEventType::UdpDatagramsSent) =>
                EventImportance::Extra,
            EventType::QuicEventType(
                QuicEventType::UdpDatagramDropped,
            ) => EventImportance::Extra,
            EventType::QuicEventType(QuicEventType::PacketReceived) =>
                EventImportance::Core,
            EventType::QuicEventType(QuicEventType::PacketSent) =>
                EventImportance::Core,
            EventType::QuicEventType(QuicEventType::PacketDropped) =>
                EventImportance::Base,
            EventType::QuicEventType(QuicEventType::PacketBuffered) =>
                EventImportance::Base,
            EventType::QuicEventType(QuicEventType::PacketsAcked) =>
                EventImportance::Extra,
            EventType::QuicEventType(
                QuicEventType::StreamStateUpdated,
            ) => EventImportance::Base,
            EventType::QuicEventType(
                QuicEventType::FramesProcessed,
            ) => EventImportance::Extra,
            EventType::QuicEventType(QuicEventType::StreamDataMoved) =>
                EventImportance::Base,
            EventType::QuicEventType(QuicEventType::DatagramDataMoved) =>
                EventImportance::Base,
            EventType::QuicEventType(QuicEventType::MigrationStateUpdated) =>
                EventImportance::Base,

            EventType::RecoveryEventType(RecoveryEventType::ParametersSet) =>
                EventImportance::Base,
            EventType::RecoveryEventType(RecoveryEventType::MetricsUpdated) =>
                EventImportance::Core,
            EventType::RecoveryEventType(
                RecoveryEventType::CongestionStateUpdated,
            ) => EventImportance::Base,
            EventType::RecoveryEventType(RecoveryEventType::LossTimerUpdated) =>
                EventImportance::Extra,
            EventType::RecoveryEventType(RecoveryEventType::PacketLost) =>
                EventImportance::Core,
            EventType::RecoveryEventType(
                RecoveryEventType::MarkedForRetransmit,
            ) => EventImportance::Extra,

            EventType::Http3EventType(Http3EventType::ParametersSet) =>
                EventImportance::Base,
            EventType::Http3EventType(Http3EventType::StreamTypeSet) =>
                EventImportance::Base,
            EventType::Http3EventType(Http3EventType::FrameCreated) =>
                EventImportance::Core,
            EventType::Http3EventType(Http3EventType::FrameParsed) =>
                EventImportance::Core,
            EventType::Http3EventType(Http3EventType::PushResolved) =>
                EventImportance::Extra,

            _ => unimplemented!(),
        }
    }
}

pub trait Eventable {
    fn importance(&self) -> EventImportance;

    fn set_time(&mut self, time: f32);
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Connectivity,
    Security,
    Transport,
    Recovery,
    Http,
    Qpack,

    Error,
    Warning,
    Info,
    Debug,
    Verbose,
    Simulation,
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let v = match self {
            EventCategory::Connectivity => "connectivity",
            EventCategory::Security => "security",
            EventCategory::Transport => "transport",
            EventCategory::Recovery => "recovery",
            EventCategory::Http => "http",
            EventCategory::Qpack => "qpack",
            EventCategory::Error => "error",
            EventCategory::Warning => "warning",
            EventCategory::Info => "info",
            EventCategory::Debug => "debug",
            EventCategory::Verbose => "verbose",
            EventCategory::Simulation => "simulation",
        };

        write!(f, "{v}",)
    }
}

impl From<EventType> for EventCategory {
    fn from(ty: EventType) -> Self {
        match ty {
            EventType::ConnectivityEventType(_) => EventCategory::Connectivity,
            EventType::SecurityEventType(_) => EventCategory::Security,
            EventType::QuicEventType(_) => EventCategory::Transport,
            EventType::RecoveryEventType(_) => EventCategory::Recovery,
            EventType::Http3EventType(_) => EventCategory::Http,

            _ => unimplemented!(),
        }
    }
}

impl From<&EventData> for EventType {
    fn from(event_data: &EventData) -> Self {
        match event_data {
            EventData::ServerListening { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ServerListening,
                ),
            EventData::ConnectionStarted { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ConnectionStarted,
                ),
            EventData::ConnectionClosed { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ConnectionClosed,
                ),
            EventData::ConnectionIdUpdated { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ConnectionIdUpdated,
                ),
            EventData::SpinBitUpdated { .. } => EventType::ConnectivityEventType(
                ConnectivityEventType::SpinBitUpdated,
            ),
            EventData::ConnectionStateUpdated { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ConnectionStateUpdated,
                ),
            EventData::PathAssigned { .. } => EventType::ConnectivityEventType(
                ConnectivityEventType::PathAssigned,
                ),
            EventData::MtuUpdated { .. } => EventType::ConnectivityEventType(
                ConnectivityEventType::MtuUpdated,
            ),

            EventData::KeyUpdated { .. } =>
                EventType::SecurityEventType(SecurityEventType::KeyUpdated),
            EventData::KeyDiscarded { .. } =>
                EventType::SecurityEventType(SecurityEventType::KeyDiscarded),

            EventData::VersionInformation { .. } =>
                EventType::QuicEventType(
                    QuicEventType::VersionInformation,
                ),
            EventData::AlpnInformation { .. } =>
                EventType::QuicEventType(QuicEventType::AlpnInformation),
            EventData::ParametersSet { .. } =>
                EventType::QuicEventType(QuicEventType::ParametersSet),
            EventData::ParametersRestored { .. } =>
                EventType::QuicEventType(
                    QuicEventType::ParametersRestored,
                ),
            EventData::UdpDatagramsReceived { .. } => EventType::QuicEventType(
                QuicEventType::UdpDatagramsReceived,
            ),
            EventData::UdpDatagramsSent { .. } =>
                EventType::QuicEventType(QuicEventType::UdpDatagramsSent),
            EventData::UdpDatagramDropped { .. } =>
                EventType::QuicEventType(QuicEventType::UdpDatagramDropped),
            EventData::PacketReceived { .. } =>
                EventType::QuicEventType(QuicEventType::PacketReceived),
            EventData::PacketSent { .. } =>
                EventType::QuicEventType(QuicEventType::PacketSent),
            EventData::PacketDropped { .. } =>
                EventType::QuicEventType(QuicEventType::PacketDropped),
            EventData::PacketBuffered { .. } =>
                EventType::QuicEventType(QuicEventType::PacketBuffered),
            EventData::PacketsAcked { .. } =>
                EventType::QuicEventType(QuicEventType::PacketsAcked),
            EventData::StreamStateUpdated { .. } =>
                EventType::QuicEventType(
                    QuicEventType::StreamStateUpdated,
                ),
            EventData::FramesProcessed { .. } =>
                EventType::QuicEventType(QuicEventType::FramesProcessed),
            EventData::StreamDataMoved { .. } =>
                EventType::QuicEventType(QuicEventType::StreamDataMoved),
            EventData::DatagramDataMoved { .. } =>
                EventType::QuicEventType(QuicEventType::DatagramDataMoved),
            EventData::MigrationStateUpdated { .. } =>
                EventType::QuicEventType(QuicEventType::MigrationStateUpdated),

            EventData::RecoveryParametersSet { .. } =>
                EventType::RecoveryEventType(RecoveryEventType::ParametersSet),
            EventData::MetricsUpdated { .. } =>
                EventType::RecoveryEventType(RecoveryEventType::MetricsUpdated),
            EventData::CongestionStateUpdated { .. } =>
                EventType::RecoveryEventType(
                    RecoveryEventType::CongestionStateUpdated,
                ),
            EventData::LossTimerUpdated { .. } =>
                EventType::RecoveryEventType(RecoveryEventType::LossTimerUpdated),
            EventData::PacketLost { .. } =>
                EventType::RecoveryEventType(RecoveryEventType::PacketLost),
            EventData::MarkedForRetransmit { .. } =>
                EventType::RecoveryEventType(
                    RecoveryEventType::MarkedForRetransmit,
                ),

            EventData::H3ParametersSet { .. } =>
                EventType::Http3EventType(Http3EventType::ParametersSet),
            EventData::H3ParametersRestored { .. } =>
                EventType::Http3EventType(Http3EventType::ParametersRestored),
            EventData::H3StreamTypeSet { .. } =>
                EventType::Http3EventType(Http3EventType::StreamTypeSet),
            EventData::H3FrameCreated { .. } =>
                EventType::Http3EventType(Http3EventType::FrameCreated),
            EventData::H3FrameParsed { .. } =>
                EventType::Http3EventType(Http3EventType::FrameParsed),
            EventData::H3PushResolved { .. } =>
                EventType::Http3EventType(Http3EventType::PushResolved),

            EventData::LogLevelError { .. } =>
                EventType::LogLevelEventType(LogLevelEventType::Error),
            EventData::LogLevelWarning { .. } =>
                EventType::LogLevelEventType(LogLevelEventType::Warning),
            EventData::LogLevelInfo { .. } =>
                EventType::LogLevelEventType(LogLevelEventType::Info),
            EventData::LogLevelDebug { .. } =>
                EventType::LogLevelEventType(LogLevelEventType::Debug),
            EventData::LogLevelVerbose { .. } =>
                EventType::LogLevelEventType(LogLevelEventType::Verbose),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DataRecipient {
    User,
    Application,
    Transport,
    Network,
    Dropped,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RawInfo {
    pub length: Option<u64>,
    pub payload_length: Option<u64>,

    pub data: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "name", content = "data")]
#[allow(clippy::large_enum_variant)]
pub enum EventData {
    // Connectivity
    #[serde(rename = "connectivity:server_listening")]
    ServerListening(connectivity::ServerListening),

    #[serde(rename = "connectivity:connection_started")]
    ConnectionStarted(connectivity::ConnectionStarted),

    #[serde(rename = "connectivity:connection_closed")]
    ConnectionClosed(connectivity::ConnectionClosed),

    #[serde(rename = "connectivity:connection_id_updated")]
    ConnectionIdUpdated(connectivity::ConnectionIdUpdated),

    #[serde(rename = "connectivity:spin_bit_updated")]
    SpinBitUpdated(connectivity::SpinBitUpdated),

    #[serde(rename = "connectivity:connection_state_updated")]
    ConnectionStateUpdated(connectivity::ConnectionStateUpdated),

    #[serde(rename = "connectivity:path_assigned")]
    PathAssigned(connectivity::PathAssigned),

    #[serde(rename = "connectivity:mtu_updated")]
    MtuUpdated(connectivity::MtuUpdated),

    // Security
    #[serde(rename = "security:key_updated")]
    KeyUpdated(security::KeyUpdated),

    #[serde(rename = "security:key_retired")]
    KeyDiscarded(security::KeyDiscarded),

    // Transport
    #[serde(rename = "quic:version_information")]
    VersionInformation(quic::quic::QuicVersionInformation),

    #[serde(rename = "quic:alpn_information")]
    AlpnInformation(quic::quic::AlpnInformation),

    #[serde(rename = "quic:parameters_set")]
    ParametersSet(quic::quic::ParametersSet),

    #[serde(rename = "quic:parameters_restored")]
    ParametersRestored(quic::quic::ParametersRestored),

    #[serde(rename = "quic:datagrams_received")]
    UdpDatagramsReceived(quic::quic::UdpDatagramsReceived),

    #[serde(rename = "quic:datagrams_sent")]
    UdpDatagramsSent(quic::quic::UdpDatagramsSent),

    #[serde(rename = "quic:datagram_dropped")]
    UdpDatagramDropped(quic::quic::UdpDatagramDropped),

    #[serde(rename = "quic:packet_received")]
    PacketReceived(quic::quic::PacketReceived),

    #[serde(rename = "quic:packet_sent")]
    PacketSent(quic::quic::PacketSent),

    #[serde(rename = "quic:packet_dropped")]
    PacketDropped(quic::quic::PacketDropped),

    #[serde(rename = "quic:packet_buffered")]
    PacketBuffered(quic::quic::PacketBuffered),

    #[serde(rename = "quic:packets_acked")]
    PacketsAcked(quic::quic::PacketsAcked),

    #[serde(rename = "quic:stream_state_updated")]
    StreamStateUpdated(quic::quic::StreamStateUpdated),

    #[serde(rename = "quic:frames_processed")]
    FramesProcessed(quic::quic::FramesProcessed),

    #[serde(rename = "quic:stream_data_moved")]
    StreamDataMoved(quic::quic::StreamDataMoved),

    #[serde(rename = "quic:datagram_data_moved")]
    DatagramDataMoved(quic::quic::DatagramDataMoved),

    #[serde(rename = "quic:migration_state_updated")]
    MigrationStateUpdated(quic::quic::MigrationStateUpdated),

    // Recovery
    #[serde(rename = "recovery:parameters_set")]
    RecoveryParametersSet(recovery::ParametersSet),

    #[serde(rename = "recovery:metrics_updated")]
    MetricsUpdated(recovery::MetricsUpdated),

    #[serde(rename = "recovery:congestion_state_updated")]
    CongestionStateUpdated(recovery::CongestionStateUpdated),

    #[serde(rename = "recovery:loss_timer_updated")]
    LossTimerUpdated(recovery::LossTimerUpdated),

    #[serde(rename = "recovery:packet_lost")]
    PacketLost(recovery::PacketLost),

    #[serde(rename = "recovery:marked_for_retransmit")]
    MarkedForRetransmit(recovery::MarkedForRetransmit),

    // HTTP/3
    #[serde(rename = "http:parameters_set")]
    H3ParametersSet(h3::ParametersSet),

    #[serde(rename = "http:parameters_restored")]
    H3ParametersRestored(h3::ParametersRestored),

    #[serde(rename = "http:stream_type_set")]
    H3StreamTypeSet(h3::StreamTypeSet),

    #[serde(rename = "http:frame_created")]
    H3FrameCreated(h3::FrameCreated),

    #[serde(rename = "http:frame_parsed")]
    H3FrameParsed(h3::FrameParsed),

    #[serde(rename = "http:push_resolved")]
    H3PushResolved(h3::PushResolved),

    // LogLevel
    #[serde(rename = "loglevel:error")]
    LogLevelError {
        code: Option<u64>,
        description: Option<String>,
    },

    #[serde(rename = "loglevel:warning")]
    LogLevelWarning {
        code: Option<u64>,
        description: Option<String>,
    },

    #[serde(rename = "loglevel:info")]
    LogLevelInfo {
        code: Option<u64>,
        description: Option<String>,
    },

    #[serde(rename = "loglevel:debug")]
    LogLevelDebug {
        code: Option<u64>,
        description: Option<String>,
    },

    #[serde(rename = "loglevel:verbose")]
    LogLevelVerbose {
        code: Option<u64>,
        description: Option<String>,
    },
}

impl EventData {
    /// Returns size of `EventData` array of `QuicFrame`s if it exists.
    pub fn contains_quic_frames(&self) -> Option<usize> {
        // For some EventData variants, the frame array is optional
        // but for others it is mandatory.
        match self {
            EventData::PacketSent(pkt) => pkt.frames.as_ref().map(|f| f.len()),

            EventData::PacketReceived(pkt) =>
                pkt.frames.as_ref().map(|f| f.len()),

            EventData::PacketLost(pkt) => pkt.frames.as_ref().map(|f| f.len()),

            EventData::MarkedForRetransmit(ev) => Some(ev.frames.len()),
            EventData::FramesProcessed(ev) => Some(ev.frames.len()),

            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LogLevelEventType {
    Error,
    Warning,
    Info,
    Debug,
    Verbose,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum ConnectionErrorCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    Value(u64),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum ApplicationErrorCode {
    ApplicationError(ApplicationError),
    Value(u64),
}

// TODO
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CryptoError {
    Prefix,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PathEndpointInfo {
    pub ip_v4: Option<String>,
    pub ip_v6: Option<String>,
    pub port_v4: Option<u16>,
    pub port_v6: Option<u16>,

    pub connection_ids: Vec<Bytes>,
}

pub mod quic;
pub mod http;