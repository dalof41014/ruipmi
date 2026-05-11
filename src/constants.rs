pub const IPMI_LANPLUS_PORT: u16 = 0x26F; // 623
pub const IPMI_CMD_TIMEOUT_SECS: f32 = 3.5;

pub const RMCP_VERSION_1: u8 = 0x06;
pub const RMCP_CLASS_IPMI: u8 = 0x07;

pub const IPMI_LANPLUS_HEADER_LEN: usize = 0x10;
pub const OFF_AUTHTYPE: usize = 0x04;
pub const OFF_PAYLOAD_TYPE: usize = 0x05;
pub const OFF_SESSION_ID: usize = 0x06;
pub const OFF_SEQUENCE_NUM: usize = 0x0A;
pub const OFF_PAYLOAD_SIZE: usize = 0x0E;

pub const PAYLOAD_TYPE_IPMI: u8 = 0x00;
pub const PAYLOAD_TYPE_RMCP_OPEN_REQUEST: u8 = 0x10;
pub const PAYLOAD_TYPE_RAKP_1: u8 = 0x12;
pub const PAYLOAD_TYPE_RAKP_3: u8 = 0x14;

pub const IPMI_RAKP_STATUS_NO_ERRORS: u8 = 0x00;

pub const IPMI_BMC_SLAVE_ADDR: u8 = 0x20;
pub const IPMI_REMOTE_SWID: u8 = 0x81;
pub const IPMI_NETFN_APP: u8 = 0x06;
pub const IPMI_CMD_CLOSE_SESSION: u8 = 0x3C;

pub const SESSION_AUTHTYPE_RMCP_PLUS: u8 = 0x06;
pub const AES_BLOCK: usize = 16;

pub const PAYLOAD_TYPE_SOL: u8 = 0x01;
pub const IPMI_CMD_ACTIVATE_PAYLOAD: u8 = 0x48;
pub const IPMI_CMD_DEACTIVATE_PAYLOAD: u8 = 0x49;
pub const SOL_PAYLOAD_TYPE_NUM: u8 = 0x01;
