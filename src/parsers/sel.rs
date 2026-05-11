//! SEL (System Event Log) parsing.

/// A parsed standard SEL entry (record type 0x02).
#[derive(Debug, Clone)]
pub struct SelEntry {
    pub record_id: u16,
    pub timestamp: u32,
    pub generator_id: u16,
    pub sensor_type: u8,
    pub sensor_number: u8,
    pub event_type: u8,
    /// true = deassertion event
    pub event_direction: bool,
    pub event_data: [u8; 3],
}

/// Parse a 16-byte standard SEL record.
pub fn parse_sel_record(data: &[u8]) -> Option<SelEntry> {
    if data.len() < 16 { return None; }
    let record_type = data[2];
    if record_type != 0x02 { return None; }

    Some(SelEntry {
        record_id: u16::from_le_bytes([data[0], data[1]]),
        timestamp: u32::from_le_bytes([data[3], data[4], data[5], data[6]]),
        generator_id: u16::from_le_bytes([data[7], data[8]]),
        sensor_type: data[10],
        sensor_number: data[11],
        event_type: data[12] & 0x7F,
        event_direction: (data[12] >> 7) & 1 == 1,
        event_data: [data[13], data[14], data[15]],
    })
}

/// Sensor type code → human-readable name (IPMI Table 42-3).
pub fn sensor_type_name(code: u8) -> &'static str {
    match code {
        0x01 => "Temperature",
        0x02 => "Voltage",
        0x03 => "Current",
        0x04 => "Fan",
        0x05 => "Physical Security",
        0x06 => "Platform Security",
        0x07 => "Processor",
        0x08 => "Power Supply",
        0x09 => "Power Unit",
        0x0C => "Memory",
        0x0D => "Drive Slot",
        0x0F => "System Firmware",
        0x10 => "Event Logging",
        0x11 => "Watchdog",
        0x12 => "System Event",
        0x13 => "Critical Interrupt",
        0x14 => "Button/Switch",
        0x19 => "Chip Set",
        0x1B => "Cable/Interconnect",
        0x1D => "System Boot",
        0x1F => "OS Boot",
        0x20 => "OS Stop",
        0x21 => "Slot/Connector",
        0x23 => "Watchdog 2",
        0x25 => "Entity Presence",
        0x27 => "LAN",
        0x28 => "Management Health",
        0x29 => "Battery",
        0x2B => "Version Change",
        0x2C => "FRU State",
        _ => "Unknown",
    }
}

/// Determine event severity from event type, offset, and sensor type.
pub fn event_severity(event_type: u8, offset: u8, sensor_type: u8) -> &'static str {
    match event_type {
        0x01 => match offset {
            0x00 | 0x01 | 0x07 | 0x08 => "Warning",
            0x02 | 0x03 | 0x04 | 0x05 | 0x09 | 0x0A | 0x0B => "Critical",
            _ => "Info",
        },
        0x02..=0x0C => match sensor_type {
            0x07 | 0x08 | 0x0C | 0x13 => "Critical",
            0x05 | 0x06 => "Warning",
            _ => "Info",
        },
        0x6F => match sensor_type {
            0x07 | 0x08 | 0x0C | 0x13 => "Critical",
            0x05 | 0x06 | 0x09 => "Warning",
            _ => "Info",
        },
        _ => "Info",
    }
}
