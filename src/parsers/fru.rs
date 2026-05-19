//! FRU (Field Replaceable Unit) parsing.

/// FRU Common Header (offset 0, 8 bytes).
#[derive(Debug, Clone)]
pub struct FruCommonHeader {
    pub format_version: u8,
    /// Offsets in 8-byte multiples (0 = area not present).
    pub internal_area_offset: u8,
    pub chassis_area_offset: u8,
    pub board_area_offset: u8,
    pub product_area_offset: u8,
    pub multirecord_area_offset: u8,
}

/// Parsed FRU board area fields.
#[derive(Debug, Clone, Default)]
pub struct FruBoardInfo {
    pub manufacturer: String,
    pub product_name: String,
    pub serial_number: String,
    pub part_number: String,
}

/// Parsed FRU product area fields.
#[derive(Debug, Clone, Default)]
pub struct FruProductInfo {
    pub manufacturer: String,
    pub product_name: String,
    pub part_number: String,
    pub version: String,
    pub serial_number: String,
    pub asset_tag: String,
}

/// Parse FRU common header from raw FRU data.
pub fn parse_fru_common_header(data: &[u8]) -> Option<FruCommonHeader> {
    if data.len() < 8 { return None; }
    Some(FruCommonHeader {
        format_version: data[0],
        internal_area_offset: data[1],
        chassis_area_offset: data[2],
        board_area_offset: data[3],
        product_area_offset: data[4],
        multirecord_area_offset: data[5],
    })
}

/// Parse FRU board area from raw FRU data.
pub fn parse_fru_board_info(data: &[u8], header: &FruCommonHeader) -> Option<FruBoardInfo> {
    if header.board_area_offset == 0 { return None; }
    let offset = header.board_area_offset as usize * 8;
    if offset + 4 > data.len() { return None; }

    // Skip: format version (1), area length (1), language (1), mfg date (3)
    let mut pos = offset + 6;
    let info = FruBoardInfo {
        manufacturer: decode_fru_field(data, &mut pos).unwrap_or_default(),
        product_name: decode_fru_field(data, &mut pos).unwrap_or_default(),
        serial_number: decode_fru_field(data, &mut pos).unwrap_or_default(),
        part_number: decode_fru_field(data, &mut pos).unwrap_or_default(),
    };
    Some(info)
}

/// Parse FRU product area from raw FRU data.
pub fn parse_fru_product_info(data: &[u8], header: &FruCommonHeader) -> Option<FruProductInfo> {
    if header.product_area_offset == 0 { return None; }
    let offset = header.product_area_offset as usize * 8;
    if offset + 4 > data.len() { return None; }

    // Skip: format version (1), area length (1), language (1)
    let mut pos = offset + 3;
    let info = FruProductInfo {
        manufacturer: decode_fru_field(data, &mut pos).unwrap_or_default(),
        product_name: decode_fru_field(data, &mut pos).unwrap_or_default(),
        part_number: decode_fru_field(data, &mut pos).unwrap_or_default(),
        version: decode_fru_field(data, &mut pos).unwrap_or_default(),
        serial_number: decode_fru_field(data, &mut pos).unwrap_or_default(),
        asset_tag: decode_fru_field(data, &mut pos).unwrap_or_default(),
    };
    Some(info)
}

/// Decode a single FRU type/length field. Advances `offset`.
pub fn decode_fru_field(data: &[u8], offset: &mut usize) -> Option<String> {
    if *offset >= data.len() { return None; }
    let tl = data[*offset];
    if tl == 0xC1 { return None; }
    let len = (tl & 0x3F) as usize;
    let typ = tl >> 6;
    *offset += 1;
    if *offset + len > data.len() { return None; }
    let raw = &data[*offset..*offset + len];
    *offset += len;
    Some(match typ {
        0 | 3 => String::from_utf8_lossy(raw).trim().to_string(),
        1 => super::decode_6bit_ascii(raw),
        2 => raw.iter().map(|b| format!("{:02X}", b)).collect(),
        _ => String::new(),
    })
}
