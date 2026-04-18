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
    pub fn requested_ip_address(&self) -> Option<[u8; 4]> {
        self.options.iter().find_map(|opt| match opt {
            Dhcpv4Option::RequestedIpAddress(ip) => Some(*ip),
            _ => None,
        })
    }

    pub fn server_identifier(&self) -> Option<[u8; 4]> {
        self.options.iter().find_map(|opt| match opt {
            Dhcpv4Option::ServerIdentifier(ip) => Some(*ip),
            _ => None,
        })
    }

    pub fn lease_time(&self) -> Option<u32> {
        self.options.iter().find_map(|opt| match opt {
            Dhcpv4Option::IpAddressLeaseTime(t) => Some(*t),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{BootpOpCode, Dhcpv4Message};
    use crate::dhcpv4::error::Dhcpv4Error;
    use crate::dhcpv4::option::{DhcpMessageType, Dhcpv4Option};
    use crate::dhcpv4::wire::Dhcpv4Wire;

    fn sample_wire<'a>(options: &'a [u8]) -> Dhcpv4Wire<'a> {
        Dhcpv4Wire {
            op: 1,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0x3903_f326,
            secs: 3,
            flags: 0x8000,
            ciaddr: [0, 0, 0, 0],
            yiaddr: [192, 168, 0, 10],
            siaddr: [192, 168, 0, 1],
            giaddr: [0, 0, 0, 0],
            chaddr: [
                0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            sname: [0u8; 64],
            file: [0u8; 128],
            options,
        }
    }

    #[test]
    fn bootp_op_code_try_from_request() {
        assert_eq!(BootpOpCode::try_from(1).unwrap(), BootpOpCode::Request);
    }

    #[test]
    fn bootp_op_code_try_from_reply() {
        assert_eq!(BootpOpCode::try_from(2).unwrap(), BootpOpCode::Reply);
    }

    #[test]
    fn bootp_op_code_try_from_invalid() {
        let err = BootpOpCode::try_from(99).unwrap_err();
        assert_eq!(err, Dhcpv4Error::InvalidBootpOpCode(99));
    }

    #[test]
    fn parse_success() {
        let options = &[
            0x63, 0x82, 0x53, 0x63, // magic cookie
            53, 1, 1, // DHCPDISCOVER
            50, 4, 192, 168, 0, 20, // Requested IP Address
            54, 4, 192, 168, 0, 1, // Server Identifier
            51, 4, 0x00, 0x01, 0x51, 0x80, // Lease Time = 86400
            255,
        ];

        let wire = sample_wire(options);
        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert_eq!(msg.op_code, BootpOpCode::Request);
        assert_eq!(msg.message_type, DhcpMessageType::Discover);
        assert_eq!(msg.htype, 1);
        assert_eq!(msg.hlen, 6);
        assert_eq!(msg.hops, 0);
        assert_eq!(msg.xid, 0x3903_f326);
        assert_eq!(msg.secs, 3);
        assert_eq!(msg.flags, 0x8000);
        assert_eq!(msg.ciaddr, [0, 0, 0, 0]);
        assert_eq!(msg.yiaddr, [192, 168, 0, 10]);
        assert_eq!(msg.siaddr, [192, 168, 0, 1]);
        assert_eq!(msg.giaddr, [0, 0, 0, 0]);
        assert_eq!(
            msg.chaddr,
            [
                0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn parse_invalid_hardware_address_length() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 1, 255];
        let mut wire = sample_wire(options);
        wire.hlen = 17;

        let err = Dhcpv4Message::parse(wire).unwrap_err();

        assert_eq!(err, Dhcpv4Error::InvalidHardwareAddressLength(17));
    }

    #[test]
    fn parse_invalid_magic_cookie_when_too_short() {
        let options = &[0x63, 0x82, 0x53];
        let wire = sample_wire(options);

        let err = Dhcpv4Message::parse(wire).unwrap_err();

        assert_eq!(err, Dhcpv4Error::InvalidMagicCookie);
    }

    #[test]
    fn parse_invalid_magic_cookie_when_value_is_wrong() {
        let options = &[0x00, 0x82, 0x53, 0x63, 53, 1, 1, 255];
        let wire = sample_wire(options);

        let err = Dhcpv4Message::parse(wire).unwrap_err();

        assert_eq!(err, Dhcpv4Error::InvalidMagicCookie);
    }

    #[test]
    fn parse_missing_message_type() {
        let options = &[0x63, 0x82, 0x53, 0x63, 50, 4, 192, 168, 0, 20, 255];
        let wire = sample_wire(options);

        let err = Dhcpv4Message::parse(wire).unwrap_err();

        assert_eq!(err, Dhcpv4Error::MissingMessageType);
    }

    #[test]
    fn decode_success() {
        let options = &[
            0x63, 0x82, 0x53, 0x63, 53, 1, 5, // DHCPACK
            54, 4, 192, 168, 0, 1, 255,
        ];
        let wire = sample_wire(options);
        let buf = wire.encode();

        let msg = Dhcpv4Message::decode(&buf).unwrap();

        assert_eq!(msg.op_code, BootpOpCode::Request);
        assert_eq!(msg.message_type, DhcpMessageType::Ack);
        assert_eq!(msg.server_identifier(), Some([192, 168, 0, 1]));
    }

    #[test]
    fn broadcast_true_when_flag_is_set() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 1, 255];
        let wire = sample_wire(options);

        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert!(msg.broadcast());
    }

    #[test]
    fn broadcast_false_when_flag_is_not_set() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 1, 255];
        let mut wire = sample_wire(options);
        wire.flags = 0;

        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert!(!msg.broadcast());
    }

    #[test]
    fn requested_ip_address_returns_some() {
        let options = &[
            0x63, 0x82, 0x53, 0x63, 53, 1, 3, 50, 4, 192, 168, 0, 20, 255,
        ];
        let wire = sample_wire(options);

        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert_eq!(msg.requested_ip_address(), Some([192, 168, 0, 20]));
    }

    #[test]
    fn requested_ip_address_returns_none() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 3, 255];
        let wire = sample_wire(options);

        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert_eq!(msg.requested_ip_address(), None);
    }

    #[test]
    fn server_identifier_returns_some() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 2, 54, 4, 192, 168, 0, 1, 255];
        let wire = sample_wire(options);

        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert_eq!(msg.server_identifier(), Some([192, 168, 0, 1]));
    }

    #[test]
    fn server_identifier_returns_none() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 2, 255];
        let wire = sample_wire(options);

        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert_eq!(msg.server_identifier(), None);
    }

    #[test]
    fn lease_time_returns_some() {
        let options = &[
            0x63, 0x82, 0x53, 0x63, 53, 1, 5, 51, 4, 0x00, 0x01, 0x51, 0x80, // 86400
            255,
        ];
        let wire = sample_wire(options);

        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert_eq!(msg.lease_time(), Some(86400));
    }

    #[test]
    fn lease_time_returns_none() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 5, 255];
        let wire = sample_wire(options);

        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert_eq!(msg.lease_time(), None);
    }

    #[test]
    fn parse_preserves_parsed_options() {
        let options = &[
            0x63, 0x82, 0x53, 0x63, 53, 1, 1, 50, 4, 192, 168, 0, 20, 54, 4, 192, 168, 0, 1, 51, 4,
            0x00, 0x01, 0x51, 0x80, 255,
        ];
        let wire = sample_wire(options);

        let msg = Dhcpv4Message::parse(wire).unwrap();

        assert_eq!(
            msg.options,
            vec![
                Dhcpv4Option::MessageType(DhcpMessageType::Discover),
                Dhcpv4Option::RequestedIpAddress([192, 168, 0, 20]),
                Dhcpv4Option::ServerIdentifier([192, 168, 0, 1]),
                Dhcpv4Option::IpAddressLeaseTime(86400),
            ]
        );
    }
}
