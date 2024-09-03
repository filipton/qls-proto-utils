use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm};
use hex_literal::hex;
use hkdf::Hkdf;
use sha2::Sha256;

const INITIAL_SALT: [u8; 20] = hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
const CLIENT_IN: [u8; 19] = hex!("00200f746c73313320636c69656e7420696e00");
const QUIC_KEY: [u8; 18] = hex!("00100e746c7331332071756963206b657900");
const QUIC_IV: [u8; 17] = hex!("000c0d746c733133207175696320697600");
const QUIC_HP: [u8; 17] = hex!("00100d746c733133207175696320687000");

#[derive(Debug)]
pub struct QuicPayload {
    pub frame_type: u8,
    pub offset: u8,
    pub length: usize,
    pub decoded_data: Vec<u8>,
}

/// Method to parse QUIC packets encoded using well-known secrets from RFC
/// (primarly Initial packet)
pub fn parse_quic_payload(data: &[u8]) -> Option<QuicPayload> {
    let mut data = data.to_vec();
    let dest_conn_len = *data.get(5)? as usize;
    let dcid = data.get(6..6 + dest_conn_len)?;

    let mut offset = 6 + dest_conn_len;
    let src_conn_len = *data.get(offset)? as usize;
    offset += src_conn_len + 1;

    let token_len = *data.get(offset)? as usize;
    offset += token_len + 1;

    //let payload_len = u16::from_be_bytes([*data.get(offset)?, *data.get(offset + 1)?]) & 0x0fff;
    offset += 2;

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

    data[0] ^= mask[0] & 0x0f;
    let packet_number_len = (data[0] & 0b00000011) as usize + 1;
    offset += packet_number_len; // payload starts here
    let mut packet_data = Vec::from(&data[offset..]);

    let header = data.get_mut(0..offset)?;
    let mut mask_i = 1;
    for i in 18..(22.min(header.len())) {
        header[i] ^= mask[mask_i];
        mask_i += 1;
    }

    let mut i = 0;
    while i < packet_number_len {
        quic_hp_iv[quic_hp_iv.len() - i - 1] ^= header[header.len() - i - 1];
        i += 1;
    }

    let mut cipher = Aes128Gcm::new_from_slice(&quic_hp_key).ok()?;
    cipher
        .decrypt_in_place(&quic_hp_iv.try_into().ok()?, &header, &mut packet_data)
        .ok()?;

    let frame_type = packet_data[0];
    let offset = packet_data[1];
    let length = (u16::from_be_bytes([packet_data[2], packet_data[3]]) & 0x0fff) as usize;

    packet_data.drain(0..4);
    Some(QuicPayload {
        frame_type,
        offset,
        length,
        decoded_data: packet_data,
    })
}
