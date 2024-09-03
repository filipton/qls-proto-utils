/// Method primary used on TCP packets (using http0.9/1/2 with ssl)
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    // buf[0] - content type
    if *buf.get(0)? != 22 {
        // not handshake
        return None;
    }

    parse_sni_inner(buf.get(5..)?)
}

/// Inner parse method (primary used on UDP QUIC packets)
pub fn parse_sni_inner(buf: &[u8]) -> Option<String> {
    let handshake_type = *buf.get(0)?; // 1byte
    if handshake_type != 1 {
        return None;
    }

    let session_id_length = *buf.get(38)? as usize; // 1byte
    let cipher_suites_len: u16 = u16::from_be_bytes([
        *buf.get(39 + session_id_length + 0)?,
        *buf.get(39 + session_id_length + 1)?,
    ]); // 2bytes

    let mut offset: usize = 39 + session_id_length + 2 + cipher_suites_len as usize;
    let compression_methods_len = *buf.get(offset)? as usize; // 1byte
    offset += 1 + compression_methods_len;

    let mut extensions_len: u16 = u16::from_be_bytes([*buf.get(offset)?, *buf.get(offset + 1)?]); // 2bytes
    offset += 2;

    while extensions_len > 0 {
        let ext_type: u16 = u16::from_be_bytes([*buf.get(offset)?, *buf.get(offset + 1)?]);
        let ext_len: u16 = u16::from_be_bytes([*buf.get(offset + 2)?, *buf.get(offset + 3)?]);
        offset += 4;

        if ext_type == 0 {
            let server_name_type = *buf.get(offset + 2)?;
            let server_name_length: u16 =
                u16::from_be_bytes([*buf.get(offset + 3)?, *buf.get(offset + 4)?]);

            let server_name = &buf.get((offset + 5)..(offset + 5 + server_name_length as usize))?;
            let server_name = core::str::from_utf8(server_name).ok()?;

            if server_name_type == 0 {
                return Some(server_name.to_string());
            }
        }

        offset += ext_len as usize;
        extensions_len -= 4 + ext_len;
    }

    None
}
