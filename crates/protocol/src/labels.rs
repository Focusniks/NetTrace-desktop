//! Keys of generated tree labels. Dissectors emit a key and arguments next to
//! the English text; the UI shows `tree.<key>` from its dictionary (see
//! `apps/desktop/src/i18n/ru.ts`) and falls back to the English text.

pub const FRAME: &str = "frame";
pub const DATA: &str = "data";
pub const MALFORMED: &str = "malformed";
pub const MALFORMED_PANIC: &str = "malformedPanic";
pub const UNREASSEMBLED: &str = "unreassembled";

pub const TCP_PAYLOAD: &str = "tcpPayload";
pub const TCP_PAYLOAD_PARTIAL: &str = "tcpPayloadPartial";
pub const TCP_OPTIONS: &str = "tcpOptions";
pub const TCP_OPTIONS_TRUNCATED: &str = "tcpOptionsTruncated";
pub const TCP_OPTIONS_MALFORMED: &str = "tcpOptionsMalformed";
pub const TCP_TIMESTAMPS: &str = "tcpTimestamps";
pub const TCP_SEQ_ACK: &str = "tcpSeqAck";
pub const TCP_ACK_TO: &str = "tcpAckTo";
pub const TCP_ANALYSIS_FLAGS: &str = "tcpAnalysisFlags";
pub const TA_FAST_RETRANSMISSION: &str = "ta.fastRetransmission";
pub const TA_RETRANSMISSION: &str = "ta.retransmission";
pub const TA_OUT_OF_ORDER: &str = "ta.outOfOrder";
pub const TA_LOST_SEGMENT: &str = "ta.lostSegment";
pub const TA_ACKED_UNSEEN: &str = "ta.ackedUnseen";
pub const TA_DUP_ACK: &str = "ta.dupAck";
pub const TA_ZERO_WINDOW: &str = "ta.zeroWindow";
pub const TA_KEEP_ALIVE: &str = "ta.keepAlive";
pub const TA_WINDOW_UPDATE: &str = "ta.windowUpdate";
pub const TA_PORT_REUSE: &str = "ta.portReuse";
pub const UDP_PAYLOAD: &str = "udpPayload";
pub const TLS_RECORD_CONTINUES: &str = "tlsRecordContinues";
pub const TLS_HANDSHAKE_CONTINUES: &str = "tlsHandshakeContinues";
pub const HTTP_HEADERS_CONTINUE: &str = "httpHeadersContinue";

/// Every key, for the test that checks the UI dictionary covers them.
pub const ALL: &[&str] = &[
    FRAME,
    DATA,
    MALFORMED,
    MALFORMED_PANIC,
    UNREASSEMBLED,
    TCP_PAYLOAD,
    TCP_PAYLOAD_PARTIAL,
    TCP_OPTIONS,
    TCP_OPTIONS_TRUNCATED,
    TCP_OPTIONS_MALFORMED,
    TCP_TIMESTAMPS,
    TCP_SEQ_ACK,
    TCP_ACK_TO,
    TCP_ANALYSIS_FLAGS,
    TA_FAST_RETRANSMISSION,
    TA_RETRANSMISSION,
    TA_OUT_OF_ORDER,
    TA_LOST_SEGMENT,
    TA_ACKED_UNSEEN,
    TA_DUP_ACK,
    TA_ZERO_WINDOW,
    TA_KEEP_ALIVE,
    TA_WINDOW_UPDATE,
    TA_PORT_REUSE,
    UDP_PAYLOAD,
    TLS_RECORD_CONTINUES,
    TLS_HANDSHAKE_CONTINUES,
    HTTP_HEADERS_CONTINUE,
];
