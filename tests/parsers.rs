use ruipmi::*;

#[test]
fn test_decode_6bit_ascii() {
    // "HELLO" in 6-bit packed: H=17, E=14, L=21, L=21, O=24
    // Each char is 6 bits, packed LSB first
    let encoded = &[0x51, 0x78, 0x65, 0x18]; // manually encoded "HELLO"
    let result = decode_6bit_ascii(encoded);
    assert!(!result.is_empty());
}

#[test]
fn test_decode_id_string_ascii() {
    // type=3 (ASCII), length=5
    let id_code = 0xC5; // (3 << 6) | 5
    let id_bytes = b"Hello World";
    let result = decode_id_string(id_code, id_bytes);
    assert_eq!(result, "Hello");
}

#[test]
fn test_sensor_type_name() {
    assert_eq!(sensor_type_name(0x01), "Temperature");
    assert_eq!(sensor_type_name(0x04), "Fan");
    assert_eq!(sensor_type_name(0x08), "Power Supply");
    assert_eq!(sensor_type_name(0x0C), "Memory");
    assert_eq!(sensor_type_name(0xFF), "Unknown");
}

#[test]
fn test_event_severity() {
    // Threshold: upper critical
    assert_eq!(event_severity(0x01, 0x02, 0x01), "Critical");
    // Threshold: upper non-critical
    assert_eq!(event_severity(0x01, 0x00, 0x01), "Warning");
    // Sensor-specific: processor
    assert_eq!(event_severity(0x6F, 0x00, 0x07), "Critical");
    // Unknown
    assert_eq!(event_severity(0xFF, 0x00, 0x00), "Info");
}

#[test]
fn test_sensor_unit_string() {
    assert_eq!(sensor_unit_string(1), "°C");
    assert_eq!(sensor_unit_string(4), "Volts");
    assert_eq!(sensor_unit_string(6), "Watts");
    assert_eq!(sensor_unit_string(18), "RPM");
    assert_eq!(sensor_unit_string(0), "");
}

#[test]
fn test_parse_sel_record() {
    // Construct a minimal 16-byte SEL record
    let mut data = [0u8; 16];
    data[0] = 0x01; data[1] = 0x00; // record_id = 1
    data[2] = 0x02; // record_type = standard
    data[3] = 0x10; data[4] = 0x20; data[5] = 0x30; data[6] = 0x40; // timestamp
    data[7] = 0x20; data[8] = 0x00; // generator_id
    data[10] = 0x01; // sensor_type = Temperature
    data[11] = 0x05; // sensor_number
    data[12] = 0x01; // event_type = threshold, direction=assertion
    data[13] = 0xAA; data[14] = 0xBB; data[15] = 0xCC;

    let entry = parse_sel_record(&data).unwrap();
    assert_eq!(entry.record_id, 1);
    assert_eq!(entry.timestamp, 0x40302010);
    assert_eq!(entry.sensor_type, 0x01);
    assert_eq!(entry.sensor_number, 5);
    assert_eq!(entry.event_type, 0x01);
    assert!(!entry.event_direction);
    assert_eq!(entry.event_data, [0xAA, 0xBB, 0xCC]);
}

#[test]
fn test_parse_sel_record_invalid() {
    // Too short
    assert!(parse_sel_record(&[0u8; 10]).is_none());
    // Wrong record type
    let mut data = [0u8; 16];
    data[2] = 0xDF; // OEM record type
    assert!(parse_sel_record(&data).is_none());
}

#[test]
fn test_parse_fru_common_header() {
    let data = [0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0xFC];
    let header = parse_fru_common_header(&data).unwrap();
    assert_eq!(header.format_version, 1);
    assert_eq!(header.board_area_offset, 1);
    assert_eq!(header.product_area_offset, 2);
}

#[test]
fn test_calc_sensor_reading() {
    let sdr = SdrFullSensor {
        common: SdrCommonSensor {
            owner_id: 0, owner_lun: 0, sensor_number: 0,
            entity_id: 0, entity_instance: 0, sensor_init: 0,
            sensor_cap: 0, sensor_type: 0x01, event_reading_type: 0x01,
            sensor_units_1: 0, sensor_units_2: 1, sensor_units_3: 0,
        },
        linearization: 0,
        m: 1,
        b: 0,
        b_exp: 0,
        r_exp: 0,
        threshold: SdrThreshold {
            upper_non_recover: 0, upper_critical: 0, upper_non_critical: 0,
            lower_non_recover: 0, lower_critical: 0, lower_non_critical: 0,
        },
        name: "Test".to_string(),
    };

    // Simple: y = 1 * 42 + 0 = 42.0
    assert_eq!(calc_sensor_reading(42, &sdr), 42.0);
    assert_eq!(calc_sensor_reading(0, &sdr), 0.0);
    assert_eq!(calc_sensor_reading(255, &sdr), 255.0);
}
