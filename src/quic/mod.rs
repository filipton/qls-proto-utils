use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm, Tag};
use hex_literal::hex;
use hkdf::Hkdf;
use sha2::Sha256;

const INITIAL_SALT: [u8; 20] = hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
const CLIENT_IN: [u8; 19] = hex!("00200f746c73313320636c69656e7420696e00");
const QUIC_KEY: [u8; 18] = hex!("00100e746c7331332071756963206b657900");
const QUIC_IV: [u8; 17] = hex!("000c0d746c733133207175696320697600");
const QUIC_HP: [u8; 17] = hex!("00100d746c733133207175696320687000");

#[derive(Debug)]
pub struct QuicHeader {
    pub header_form: u8,
    pub fixed_bit: u8,
    pub packet_type: u8,
    pub enc_packet_bits: u8,

    pub version: u32,
}

#[derive(Debug)]
pub struct QuicPayload {
    pub frame_type: u64,
    pub offset: usize,
    pub length: usize,
    pub decoded_data: Vec<u8>,
}

pub fn parse_quic_header(data: &[u8]) -> Option<QuicHeader> {
    let f_byte = data.get(0)?;
    Some(QuicHeader {
        header_form: (f_byte & 0b10000000) >> 7,
        fixed_bit: (f_byte & 0b01000000) >> 6,
        packet_type: (f_byte & 0b00110000) >> 4,
        enc_packet_bits: f_byte & 0b00001111,
        version: u32::from_be_bytes(data.get(1..5)?.try_into().ok()?),
    })
}

/// Method to parse QUIC packets encoded using well-known secrets from RFC
/// (primarly Initial packet)
pub fn parse_quic_payload(mut header: QuicHeader, data: &mut [u8]) -> Option<QuicPayload> {
    let dest_conn_len = *data.get(5)? as usize;
    let dcid = data.get(6..6 + dest_conn_len)?;

    let mut offset = 6 + dest_conn_len;
    let src_conn_len = *data.get(offset)? as usize;
    offset += src_conn_len + 1;

    let (token_len, len) = read_variable_length_int(&data[offset..]);
    offset += token_len as usize + len;

    let (_, len) = read_variable_length_int(&data[offset..]);
    offset += len;

    let hk = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), &dcid);
    let mut client_initial_secret = [0; 32];
    hk.expand(&CLIENT_IN, &mut client_initial_secret).ok()?;

    let hk = Hkdf::<Sha256>::from_prk(&client_initial_secret).ok()?;
    let mut quic_hp_key = [0; 16];
    hk.expand(&QUIC_KEY, &mut quic_hp_key).ok()?;

    let mut quic_hp_iv = [0; 12];
    hk.expand(&QUIC_IV, &mut quic_hp_iv).ok()?;

    let mut quic_hp_secret = [0; 16];
    hk.expand(&QUIC_HP, &mut quic_hp_secret).ok()?;

    let cipher = aes::Aes128::new_from_slice(&quic_hp_secret).ok()?;
    let mut sample = data.get((offset + 4)..(offset + 20))?.to_vec();
    let mut block = aes::Block::from_mut_slice(&mut sample);
    cipher.encrypt_block(&mut block);
    let mask = &block[..5];

    header.enc_packet_bits ^= mask[0] & 0x0f;
    let packet_number_len = (header.enc_packet_bits & 0b00000011) as usize + 1;
    offset += packet_number_len; // payload starts here

    let header_bytes = data.get_mut(0..offset)?;
    let mut mask_i = 1;
    for i in (offset - packet_number_len)..offset {
        header_bytes[i] ^= mask[mask_i];
        mask_i += 1;
    }

    let mut i = 0;
    while i < packet_number_len {
        quic_hp_iv[quic_hp_iv.len() - i - 1] ^= header_bytes[header_bytes.len() - i - 1];
        i += 1;
    }

    let (aad, packet_data) = data.split_at_mut(offset);
    let mut cipher = Aes128Gcm::new_from_slice(&quic_hp_key).ok()?;

    let tag_pos = packet_data.len() - 16; // 16 - u16
    let (msg, tag) = packet_data.split_at_mut(tag_pos);
    cipher
        .decrypt_in_place_detached(&quic_hp_iv.try_into().ok()?, aad, msg, Tag::from_slice(tag))
        .ok()?;
    println!("\n\nmsg_dec:{msg:02X?}");

    let mut packet_offset = 0;
    let (frame_type, len) = read_variable_length_int(&packet_data[packet_offset..]);
    packet_offset += len;

    let (offset, len) = read_variable_length_int(&packet_data[packet_offset..]);
    packet_offset += len;

    let (length, len) = read_variable_length_int(&packet_data[packet_offset..]);
    packet_offset += len;

    Some(QuicPayload {
        frame_type,
        offset: offset as usize,
        length: length as usize,
        decoded_data: Vec::from(&packet_data[packet_offset..]),
    })
}

fn read_variable_length_int(data: &[u8]) -> (u64, usize) {
    let two_msb = data[0] & 0b11000000;
    let len: usize = match two_msb {
        0b00000000 => 1,
        0b01000000 => 2,
        0b10000000 => 4,
        0b11000000 => 8,
        _ => 0,
    };

    let mut tmp = [0; 8];
    tmp[(8 - len)..8].copy_from_slice(&data[..len]);
    tmp[8 - len] &= 0b00111111;

    (u64::from_be_bytes(tmp), len)
}
