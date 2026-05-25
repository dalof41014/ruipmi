//! SDR (Sensor Data Record) parsing.

/// SDR record header (5 bytes).
#[derive(Debug, Clone, Copy)]
pub struct SdrHeader {
    pub record_id: u16,
    pub version: u8,
    pub record_type: u8,
    pub record_length: u8,
}

/// Common sensor fields shared by Full and Compact SDR records.
#[derive(Debug, Clone, Copy)]
pub struct SdrCommonSensor {
    pub owner_id: u8,
    pub owner_lun: u8,
    pub sensor_number: u8,
    pub entity_id: u8,
    pub entity_instance: u8,
    pub sensor_init: u8,
    pub sensor_cap: u8,
    pub sensor_type: u8,
    pub event_reading_type: u8,
    pub sensor_units_1: u8,
    pub sensor_units_2: u8,
    pub sensor_units_3: u8,
}

/// Threshold values for a full sensor record.
#[derive(Debug, Clone, Copy)]
pub struct SdrThreshold {
    pub upper_non_recover: u8,
    pub upper_critical: u8,
    pub upper_non_critical: u8,
    pub lower_non_recover: u8,
    pub lower_critical: u8,
    pub lower_non_critical: u8,
}

/// Full Sensor Record (SDR Type 0x01).
#[derive(Debug, Clone)]
pub struct SdrFullSensor {
    pub common: SdrCommonSensor,
    pub linearization: u8,
    pub m: i16,
    pub b: i16,
    pub b_exp: i8,
    pub r_exp: i8,
    pub threshold: SdrThreshold,
    pub name: String,
}

/// Compact Sensor Record (SDR Type 0x02).
#[derive(Debug, Clone)]
pub struct SdrCompactSensor {
    pub common: SdrCommonSensor,
    pub name: String,
}

/// Parsed SDR record.
#[derive(Debug, Clone)]
pub enum SdrRecord {
    Full(SdrFullSensor),
    Compact(SdrCompactSensor),
    Unknown(u8),
}

/// Parse SDR header from 5 bytes.
pub fn parse_sdr_header(data: &[u8]) -> Option<SdrHeader> {
    if data.len() < 5 { return None; }
    Some(SdrHeader {
        record_id: u16::from_le_bytes([data[0], data[1]]),
        version: data[2],
        record_type: data[3],
        record_length: data[4],
    })
}

/// Parse an SDR record body (after the 5-byte header).
pub fn parse_sdr_record(header: &SdrHeader, body: &[u8]) -> SdrRecord {
    match header.record_type {
        0x01 if body.len() >= 41 => parse_full_sensor(body),
        0x02 if body.len() >= 25 => parse_compact_sensor(body),
        t => SdrRecord::Unknown(t),
    }
}

fn parse_common_sensor(body: &[u8]) -> SdrCommonSensor {
    SdrCommonSensor {
        owner_id: body[0],
        owner_lun: body[1],
        sensor_number: body[2],
        entity_id: body[3],
        entity_instance: body[4],
        sensor_init: body[5],
        sensor_cap: body[6],
        sensor_type: body[7],
        event_reading_type: body[8],
        // body[9..14] = assertion/deassertion/reading masks (skipped)
        sensor_units_1: body[15],
        sensor_units_2: body[16],
        sensor_units_3: body[17],
    }
}

fn parse_full_sensor(body: &[u8]) -> SdrRecord {
    let common = parse_common_sensor(body);

    // IPMI v2.0 Table 43-1: Full Sensor Record - SDR body offsets
    let linearization = body[18] & 0x7F;

    let m = sign_extend_10(((body[20] as u16 & 0xC0) << 2) | body[19] as u16);
    let b_raw = ((body[22] as u16 & 0xC0) << 2) | body[21] as u16;
    let b = sign_extend_10(b_raw);
    let r_exp = sign4(body[24] >> 4);
    let b_exp = sign4(body[24] & 0x0F);

    let threshold = SdrThreshold {
        upper_non_recover: body[34],
        upper_critical: body[35],
        upper_non_critical: body[36],
        lower_non_recover: body[37],
        lower_critical: body[38],
        lower_non_critical: body[39],
    };

    let id_code = body[40];
    let id_bytes = &body[41..];
    let name = super::decode_id_string(id_code, id_bytes);

    SdrRecord::Full(SdrFullSensor {
        common,
        linearization,
        m,
        b,
        b_exp,
        r_exp,
        threshold,
        name,
    })
}

fn parse_compact_sensor(body: &[u8]) -> SdrRecord {
    let common = parse_common_sensor(body);
    let id_code = body[24];
    let id_bytes = &body[25..];
    let name = super::decode_id_string(id_code, id_bytes);
    SdrRecord::Compact(SdrCompactSensor { common, name })
}

/// Calculate a sensor reading value from raw byte using SDR linearization formula.
/// `y = (M * x + B * 10^Bexp) * 10^Rexp`
pub fn calc_sensor_reading(raw: u8, sdr: &SdrFullSensor) -> f32 {
    let x = raw as f32;
    let m = sdr.m as f32;
    let b = sdr.b as f32;
    let mut y = (m * x + b * 10f32.powi(sdr.b_exp as i32)) * 10f32.powi(sdr.r_exp as i32);

    y = match sdr.linearization {
        0x00 => y,
        0x01 => y.ln(),
        0x02 => y.log10(),
        0x03 => y.log2(),
        0x04 => y.exp(),
        0x05 => 10f32.powf(y),
        0x06 => 2f32.powf(y),
        0x07 => if y != 0.0 { 1.0 / y } else { 0.0 },
        0x08 => y * y,
        0x09 => y * y * y,
        0x0A => y.sqrt(),
        0x0B => y.cbrt(),
        _ => y,
    };
    y
}

#[inline]
fn sign_extend_10(x: u16) -> i16 {
    let v = (x & 0x03FF) as i16;
    if (v & 0x0200) != 0 { v | !0x03FF } else { v }
}

#[inline]
fn sign4(v: u8) -> i8 {
    let r = (v & 0x0F) as i8;
    if (r & 0x08) != 0 { r - 16 } else { r }
}
