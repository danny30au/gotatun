use std::fmt::{self, Debug};

use eyre::{bail, eyre};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, little_endian};

use crate::packet::Packet;

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct Wg {
    pub packet_type: WgPacketType,
    rest: [u8],
}

#[derive(Clone)]
pub enum WgKind {
    HandshakeInit(Packet<WgHandshakeInit>),
    HandshakeResp(Packet<WgHandshakeResp>),
    CookieReply(Packet<WgCookieReply>),
    Data(Packet<WgData>),
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct WgPacketType(pub little_endian::U32);

impl WgPacketType {
    #![allow(non_upper_case_globals)]
    pub const HandshakeInit: WgPacketType = WgPacketType(little_endian::U32::new(1));
    pub const HandshakeResp: WgPacketType = WgPacketType(little_endian::U32::new(2));
    pub const CookieReply: WgPacketType = WgPacketType(little_endian::U32::new(3));
    pub const Data: WgPacketType = WgPacketType(little_endian::U32::new(4));
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgData {
    // INVARIANT: Must be WgPacketType::Data
    packet_type: WgPacketType,

    pub receiver_idx: little_endian::U32,
    pub counter: little_endian::U64,
    pub encrypted_encapsulated_packet: [u8],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgHandshakeInit {
    // INVARIANT: Must be WgPacketType::HandshakeInit
    packet_type: WgPacketType,

    pub sender_idx: little_endian::U32,
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    _what_this: [u8; 32],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgHandshakeResp {
    // INVARIANT: Must be WgPacketType::HandshakeResp
    packet_type: WgPacketType,

    pub sender_idx: little_endian::U32,
    pub receiver_idx: little_endian::U32,
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_nothing: [u8; 16],
    _what_this: [u8; 32],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgCookieReply {
    // INVARIANT: Must be WgPacketType::CookieReply
    packet_type: WgPacketType,

    pub receiver_idx: little_endian::U32,
    pub nonce: [u8; 24],
    pub encrypted_cookie: [u8; 32],
}

// TODO: DRY
const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

impl Packet {
    /// Convert into a wireguard packet while sanity-checking packet type and size.
    pub fn try_into_wg(self) -> eyre::Result<Packet<Wg>> {
        let len = self.len();
        let wg = Wg::ref_from_bytes(self.as_bytes())
            .map_err(|_| eyre!("Not a wireguard packet, too small."))?;

        Ok(self.cast())
    }
}

impl Packet<Wg> {
    pub fn into_kind(self) -> eyre::Result<WgKind> {
        let len = self.as_bytes().len();
        match (self.packet_type, len) {
            (WgPacketType::HandshakeInit, HANDSHAKE_INIT_SZ) => {
                Ok(WgKind::HandshakeInit(self.cast()))
            }
            (WgPacketType::HandshakeResp, HANDSHAKE_RESP_SZ) => {
                Ok(WgKind::HandshakeResp(self.cast()))
            }
            (WgPacketType::CookieReply, COOKIE_REPLY_SZ) => Ok(WgKind::CookieReply(self.cast())),
            (WgPacketType::Data, DATA_OVERHEAD_SZ..) => Ok(WgKind::Data(self.cast())),
            _ => bail!("Not a wireguard packet, bad type/size."),
        }
    }
}

impl Debug for WgPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            &WgPacketType::HandshakeInit => "HandshakeInit",
            &WgPacketType::HandshakeResp => "HandshakeResp",
            &WgPacketType::CookieReply => "CookieReply",
            &WgPacketType::Data => "Data",

            WgPacketType(t) => return Debug::fmt(t, f),
        };

        f.debug_tuple(name).finish()
    }
}
