use alloc::vec::Vec;

use crate::dhcpv4::error::Dhcpv4Error;
use crate::dhcpv4::option::{DhcpMessageType, Dhcpv4Option};
use crate::dhcpv4::wire::Dhcpv4Wire;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootpOpCode {
    Request = 1,
    Reply = 2,
}

impl core::convert::TryFrom<u8> for BootpOpCode {
    type Error = Dhcpv4Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(BootpOpCode::Request),
            2 => Ok(BootpOpCode::Reply),
            v => Err(Dhcpv4Error::InvalidBootpOpCode(v)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Dhcpv4Message<'a> {
    pub op_code: BootpOpCode,
    pub message_type: DhcpMessageType,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<Dhcpv4Option<'a>>,
}

impl<'a> Dhcpv4Message<'a> {
    const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

    pub fn parse(wire: Dhcpv4Wire<'a>) -> Result<Self, Dhcpv4Error> {
        let op_code = BootpOpCode::try_from(wire.op)?;

        if wire.hlen as usize > wire.chaddr.len() {
            return Err(Dhcpv4Error::InvalidHardwareAddressLength(wire.hlen));
        }

        let options = wire.options;

        if options.len() < Self::DHCP_MAGIC_COOKIE.len() {
            return Err(Dhcpv4Error::InvalidMagicCookie);
        }

        if options[..4] != Self::DHCP_MAGIC_COOKIE {
            return Err(Dhcpv4Error::InvalidMagicCookie);
        }

        let dhcp_options = Dhcpv4Option::parse(&options[4..])?;
        let message_type = dhcp_options
            .iter()
            .find_map(|opt| match opt {
                Dhcpv4Option::MessageType(t) => Some(*t),
                _ => None,
            })
            .ok_or(Dhcpv4Error::MissingMessageType)?;

        Ok(Self {
            op_code,
            message_type,
            htype: wire.htype,
            hlen: wire.hlen,
            hops: wire.hops,
            xid: wire.xid,
            secs: wire.secs,
            flags: wire.flags,
            ciaddr: wire.ciaddr,
            yiaddr: wire.yiaddr,
            siaddr: wire.siaddr,
            giaddr: wire.giaddr,
            chaddr: wire.chaddr,
            sname: wire.sname,
            file: wire.file,
            options: dhcp_options,
        })
    }

    pub fn decode(buf: &'a [u8]) -> Result<Self, Dhcpv4Error> {
        let wire = Dhcpv4Wire::decode(buf)?;
        Self::parse(wire)
    }

    pub fn broadcast(&self) -> bool {
        (self.flags & 0x8000) != 0
    }
}
