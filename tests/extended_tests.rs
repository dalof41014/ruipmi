use ruipmi::*;

#[test]
fn test_sdr_header_parse() {
    // record_id=0x0001, version=0x51, record_type=0x01, length=48
    let data = [0x01, 0x00, 0x51, 0x01, 0x30];
    let header = parse_sdr_header(&data).unwrap();
    assert_eq!(header.record_id, 1);
    assert_eq!(header.version, 0x51);
    assert_eq!(header.record_type, 0x01);
    assert_eq!(header.record_length, 48);
}

#[test]
fn test_sdr_header_too_short() {
    assert!(parse_sdr_header(&[0x01, 0x00]).is_none());
    assert!(parse_sdr_header(&[]).is_none());
}

#[test]
fn test_calc_sensor_reading_with_m_and_b() {
    let sdr = SdrFullSensor {
        common: SdrCommonSensor {
            owner_id: 0, owner_lun: 0, sensor_number: 1,
            entity_id: 0, entity_instance: 0, sensor_init: 0,
            sensor_cap: 0, sensor_type: 0x01, event_reading_type: 0x01,
            sensor_units_1: 0, sensor_units_2: 1, sensor_units_3: 0,
        },
        linearization: 0,
        m: 2,
        b: 10,
        b_exp: 0,
        r_exp: 0,
        threshold: SdrThreshold {
            upper_non_recover: 0, upper_critical: 0, upper_non_critical: 0,
            lower_non_recover: 0, lower_critical: 0, lower_non_critical: 0,
        },
        name: "CPU Temp".to_string(),
    };

    // y = (2 * 100 + 10) * 10^0 = 210.0
    assert_eq!(calc_sensor_reading(100, &sdr), 210.0);
    // y = (2 * 0 + 10) * 10^0 = 10.0
    assert_eq!(calc_sensor_reading(0, &sdr), 10.0);
}

#[test]
fn test_calc_sensor_reading_with_exponent() {
    let sdr = SdrFullSensor {
        common: SdrCommonSensor {
            owner_id: 0, owner_lun: 0, sensor_number: 1,
            entity_id: 0, entity_instance: 0, sensor_init: 0,
            sensor_cap: 0, sensor_type: 0x04, event_reading_type: 0x01,
            sensor_units_1: 0, sensor_units_2: 18, sensor_units_3: 0,
        },
        linearization: 0,
        m: 1,
        b: 0,
        b_exp: 0,
        r_exp: 2, // multiply by 100
        threshold: SdrThreshold {
            upper_non_recover: 0, upper_critical: 0, upper_non_critical: 0,
            lower_non_recover: 0, lower_critical: 0, lower_non_critical: 0,
        },
        name: "Fan RPM".to_string(),
    };

    // y = (1 * 50 + 0) * 10^2 = 5000.0
    assert_eq!(calc_sensor_reading(50, &sdr), 5000.0);
}

#[test]
fn test_sensor_type_names() {
    assert_eq!(sensor_type_name(0x01), "Temperature");
    assert_eq!(sensor_type_name(0x02), "Voltage");
    assert_eq!(sensor_type_name(0x03), "Current");
    assert_eq!(sensor_type_name(0x04), "Fan");
    assert_eq!(sensor_type_name(0x05), "Physical Security");
    assert_eq!(sensor_type_name(0x07), "Processor");
    assert_eq!(sensor_type_name(0x08), "Power Supply");
    assert_eq!(sensor_type_name(0x0C), "Memory");
    assert_eq!(sensor_type_name(0x0D), "Drive Slot");
    assert_eq!(sensor_type_name(0x14), "Button/Switch");
}

#[test]
fn test_sensor_unit_strings() {
    assert_eq!(sensor_unit_string(0), "");
    assert_eq!(sensor_unit_string(1), "°C");
    assert_eq!(sensor_unit_string(2), "°F");
    assert_eq!(sensor_unit_string(4), "Volts");
    assert_eq!(sensor_unit_string(5), "Amps");
    assert_eq!(sensor_unit_string(6), "Watts");
    assert_eq!(sensor_unit_string(18), "RPM");
}

#[test]
fn test_event_severity_threshold() {
    // Upper non-critical going high
    assert_eq!(event_severity(0x01, 0x00, 0x01), "Warning");
    // Upper critical going high
    assert_eq!(event_severity(0x01, 0x02, 0x01), "Critical");
    // Upper non-recoverable going high
    assert_eq!(event_severity(0x01, 0x04, 0x01), "Critical");
    // Lower non-critical going low
    assert_eq!(event_severity(0x01, 0x01, 0x01), "Warning");
    // Lower critical going low
    assert_eq!(event_severity(0x01, 0x03, 0x01), "Critical");
}

#[test]
fn test_event_severity_discrete() {
    // Sensor-specific events
    assert_eq!(event_severity(0x6F, 0x00, 0x07), "Critical"); // Processor IERR
    assert_eq!(event_severity(0x6F, 0x00, 0x0C), "Critical"); // Memory
}

#[test]
fn test_decode_id_string_types() {
    // ASCII type (type=3)
    let id_code = 0xC5; // (3 << 6) | 5
    assert_eq!(decode_id_string(id_code, b"ABCDE"), "ABCDE");

    // Empty string
    let id_code = 0xC0; // (3 << 6) | 0
    assert_eq!(decode_id_string(id_code, b""), "");
}

#[test]
fn test_decode_6bit_ascii_empty() {
    let result = decode_6bit_ascii(&[]);
    assert_eq!(result, "");
}

#[test]
fn test_parse_sel_record_standard() {
    let mut data = [0u8; 16];
    data[0] = 0x05; data[1] = 0x00; // record_id = 5
    data[2] = 0x02; // record_type = standard (0x02)
    data[3] = 0x00; data[4] = 0x00; data[5] = 0x00; data[6] = 0x00; // timestamp = 0
    data[7] = 0x20; data[8] = 0x00; // generator_id
    data[9] = 0x04; // evm_rev
    data[10] = 0x04; // sensor_type = Fan
    data[11] = 0x0A; // sensor_number = 10
    data[12] = 0x81; // event_type=0x01, direction=deassertion (bit7=1)
    data[13] = 0x01; data[14] = 0x02; data[15] = 0x03;

    let entry = parse_sel_record(&data).unwrap();
    assert_eq!(entry.record_id, 5);
    assert_eq!(entry.sensor_type, 0x04);
    assert_eq!(entry.sensor_number, 10);
    assert_eq!(entry.event_type, 0x01);
    assert!(entry.event_direction); // deassertion
    assert_eq!(entry.event_data, [0x01, 0x02, 0x03]);
}

#[test]
fn test_parse_fru_common_header_valid() {
    // version=1, internal=0, chassis=0, board=1(offset*8=8), product=2(offset*8=16), multirecord=0, pad=0, checksum
    let mut data = [0u8; 8];
    data[0] = 0x01; // version
    data[3] = 0x01; // board area offset
    data[4] = 0x02; // product area offset
    // Calculate checksum
    let sum: u8 = data[0..7].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    data[7] = (!sum).wrapping_add(1);

    let header = parse_fru_common_header(&data).unwrap();
    assert_eq!(header.format_version, 1);
    assert_eq!(header.board_area_offset, 1);
    assert_eq!(header.product_area_offset, 2);
}

#[test]
fn test_parse_fru_common_header_invalid() {
    // Too short
    assert!(parse_fru_common_header(&[0x01, 0x00]).is_none());
}

#[test]
fn test_cipher_suite_variants() {
    let suite = CipherSuite {
        authentication: AuthAlg::HmacSha1,
        integrity: IntegrityAlg::HmacSha1_96,
        confidentiality: CryptAlg::AesCbc128,
    };
    assert_eq!(suite.auth_byte(), 0x01);
    assert_eq!(suite.integrity_byte(), 0x01);
    assert_eq!(suite.conf_byte(), 0x01);
    assert_eq!(suite.auth_digest_len(), 20);
    assert_eq!(suite.integrity_truncate_len(), 12);
}

#[test]
fn test_cipher_suite_none() {
    let suite = CipherSuite {
        authentication: AuthAlg::None,
        integrity: IntegrityAlg::None,
        confidentiality: CryptAlg::None,
    };
    assert_eq!(suite.auth_byte(), 0x00);
    assert_eq!(suite.integrity_byte(), 0x00);
    assert_eq!(suite.conf_byte(), 0x00);
    assert_eq!(suite.auth_digest_len(), 0);
    assert_eq!(suite.integrity_truncate_len(), 0);
}

#[test]
fn test_cipher_suite_sha256() {
    let suite = CipherSuite {
        authentication: AuthAlg::HmacSha256,
        integrity: IntegrityAlg::HmacSha256_128,
        confidentiality: CryptAlg::AesCbc128,
    };
    assert_eq!(suite.auth_byte(), 0x03);
    assert_eq!(suite.integrity_byte(), 0x04);
    assert_eq!(suite.auth_digest_len(), 32);
    assert_eq!(suite.integrity_truncate_len(), 16);
}
