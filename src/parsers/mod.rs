//! IPMI data parsers for SDR, SEL, and FRU records.

mod fru;
mod sdr;
mod sel;

pub use fru::*;
pub use sdr::*;
pub use sel::*;

/// Decode 6-bit packed ASCII (IPMI spec encoding type 1).
pub fn decode_6bit_ascii(data: &[u8]) -> String {
    let mut out = String::new();
    let mut bits = 0u32;
    let mut bit_count = 0u8;
    for &b in data {
        bits |= (b as u32) << bit_count;
        bit_count += 8;
        while bit_count >= 6 {
            let c = (bits & 0x3F) as u8;
            bits >>= 6;
            bit_count -= 6;
            out.push(match c {
                0..=9 => (b'0' + c) as char,
                10..=35 => (b'A' + (c - 10)) as char,
                36..=61 => (b'a' + (c - 36)) as char,
                62 => '+',
                63 => '/',
                _ => '?',
            });
        }
    }
    out
}

/// Decode SDR/FRU ID string based on type/length byte.
pub fn decode_id_string(id_code: u8, id_bytes: &[u8]) -> String {
    let len = (id_code & 0x3F) as usize;
    let typ = id_code >> 6;
    let raw = &id_bytes[..len.min(id_bytes.len())];
    match typ {
        0 | 3 => String::from_utf8_lossy(raw).to_string(),
        1 => decode_6bit_ascii(raw),
        2 => raw.iter().map(|b| format!("{:02X}", b)).collect(),
        _ => "<unknown>".to_string(),
    }
}

/// Sensor unit code → string (IPMI Table 43-15).
pub fn sensor_unit_string(unit_code: u8) -> &'static str {
    match unit_code {
        0 => "",
        1 => "°C",
        2 => "°F",
        3 => "K",
        4 => "Volts",
        5 => "Amps",
        6 => "Watts",
        7 => "Joules",
        18 => "RPM",
        19 => "Hz",
        20 => "us",
        21 => "ms",
        22 => "s",
        23 => "min",
        24 => "hr",
        _ => "",
    }
}
