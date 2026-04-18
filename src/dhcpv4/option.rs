use crate::dhcpv4::error::Dhcpv4Error;
use crate::wire;

extern crate alloc;
use alloc::vec::Vec;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl TryFrom<u8> for DhcpMessageType {
    type Error = Dhcpv4Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Offer),
            3 => Ok(Self::Request),
            4 => Ok(Self::Decline),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Release),
            8 => Ok(Self::Inform),
            v => Err(Dhcpv4Error::InvalidMessageType(v)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Dhcpv4Option<'a> {
    MessageType(DhcpMessageType),
    RequestedIpAddress([u8; 4]),
    IpAddressLeaseTime(u32),
    ServerIdentifier([u8; 4]),
    ParameterRequestList(&'a [u8]),
    HostName(&'a [u8]),
    ClientIdentifier(&'a [u8]),
    Other { code: u8, value: &'a [u8] },
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dhcpv4OptionCode {
    HostName = 12,
    RequestedIpAddress = 50,
    IpAddressLeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    ClientIdentifier = 61,
}

impl<'a> Dhcpv4Option<'a> {
    const OPTION_CODE_PAD: u8 = 0;
    const OPTION_CODE_END: u8 = 255;

    pub fn parse(buf: &'a [u8]) -> Result<Vec<Dhcpv4Option<'a>>, Dhcpv4Error> {
        let mut reader = wire::Reader::new(buf);
        let mut options = Vec::new();

        loop {
            let code = reader.read_u8()?;

            if code == Self::OPTION_CODE_PAD {
                continue;
            }
            if code == Self::OPTION_CODE_END {
                break;
            }

            let len = reader.read_u8()? as usize;
            let value = reader.read_slice(len)?;

            let option = match code {
                x if x == Dhcpv4OptionCode::MessageType as u8 => {
                    if value.len() != 1 {
                        return Err(Dhcpv4Error::InvalidOptionLength(code));
                    }
                    Dhcpv4Option::MessageType(DhcpMessageType::try_from(value[0])?)
                }
                x if x == Dhcpv4OptionCode::RequestedIpAddress as u8 => {
                    if value.len() != 4 {
                        return Err(Dhcpv4Error::InvalidOptionLength(code));
                    }
                    Dhcpv4Option::RequestedIpAddress(value.try_into().unwrap())
                }
                x if x == Dhcpv4OptionCode::IpAddressLeaseTime as u8 => {
                    if value.len() != 4 {
                        return Err(Dhcpv4Error::InvalidOptionLength(code));
                    }
                    Dhcpv4Option::IpAddressLeaseTime(u32::from_be_bytes(value.try_into().unwrap()))
                }
                x if x == Dhcpv4OptionCode::ServerIdentifier as u8 => {
                    if value.len() != 4 {
                        return Err(Dhcpv4Error::InvalidOptionLength(code));
                    }
                    Dhcpv4Option::ServerIdentifier(value.try_into().unwrap())
                }
                x if x == Dhcpv4OptionCode::ParameterRequestList as u8 => {
                    Dhcpv4Option::ParameterRequestList(value)
                }
                x if x == Dhcpv4OptionCode::HostName as u8 => Dhcpv4Option::HostName(value),
                x if x == Dhcpv4OptionCode::ClientIdentifier as u8 => {
                    Dhcpv4Option::ClientIdentifier(value)
                }
                other_code => Dhcpv4Option::Other {
                    code: other_code,
                    value,
                },
            };

            options.push(option);
        }

        Ok(options)
    }
}

#[cfg(test)]
mod tests {
    use super::{DhcpMessageType, Dhcpv4Option};
    use crate::dhcpv4::error::Dhcpv4Error;

    #[test]
    fn parse_message_type() {
        let buf = [
            53, 1, 1,   // DHCP Message Type = DHCPDISCOVER
            255, // End
        ];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(
            options,
            vec![Dhcpv4Option::MessageType(DhcpMessageType::Discover)]
        );
    }

    #[test]
    fn parse_requested_ip_address() {
        let buf = [50, 4, 192, 168, 0, 10, 255];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(
            options,
            vec![Dhcpv4Option::RequestedIpAddress([192, 168, 0, 10])]
        );
    }

    #[test]
    fn parse_ip_address_lease_time() {
        let buf = [
            51, 4, 0x00, 0x01, 0x51, 0x80, // 86400 (1 day)
            255,
        ];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(options, vec![Dhcpv4Option::IpAddressLeaseTime(86400)]);
    }

    #[test]
    fn parse_ip_address_lease_time_invalid_length() {
        let buf = [51, 3, 0x00, 0x01, 0x51, 255];

        let err = Dhcpv4Option::parse(&buf).unwrap_err();

        assert_eq!(err, Dhcpv4Error::InvalidOptionLength(51));
    }

    #[test]
    fn parse_ip_address_lease_time_wire_error_short_value() {
        let buf = [
            51, 4, 0x00, 0x01, // 足りない
        ];

        let err = Dhcpv4Option::parse(&buf).unwrap_err();

        assert!(matches!(err, Dhcpv4Error::Wire(_)));
    }

    #[test]
    fn parse_server_identifier() {
        let buf = [54, 4, 192, 168, 0, 1, 255];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(
            options,
            vec![Dhcpv4Option::ServerIdentifier([192, 168, 0, 1])]
        );
    }

    #[test]
    fn parse_parameter_request_list() {
        let buf = [55, 3, 1, 3, 6, 255];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(
            options,
            vec![Dhcpv4Option::ParameterRequestList(&[1, 3, 6])]
        );
    }

    #[test]
    fn parse_host_name() {
        let buf = [12, 4, b't', b'e', b's', b't', 255];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(options, vec![Dhcpv4Option::HostName(b"test")]);
    }

    #[test]
    fn parse_client_identifier() {
        let buf = [61, 7, 1, 0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc, 255];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(
            options,
            vec![Dhcpv4Option::ClientIdentifier(&[
                1, 0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc
            ])]
        );
    }

    #[test]
    fn parse_other_option() {
        let buf = [99, 2, 0x12, 0x34, 255];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(
            options,
            vec![Dhcpv4Option::Other {
                code: 99,
                value: &[0x12, 0x34],
            }]
        );
    }

    #[test]
    fn parse_multiple_options() {
        let buf = [53, 1, 1, 50, 4, 192, 168, 0, 10, 55, 3, 1, 3, 6, 255];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(
            options,
            vec![
                Dhcpv4Option::MessageType(DhcpMessageType::Discover),
                Dhcpv4Option::RequestedIpAddress([192, 168, 0, 10]),
                Dhcpv4Option::ParameterRequestList(&[1, 3, 6]),
            ]
        );
    }

    #[test]
    fn parse_ignores_pad_option() {
        let buf = [0, 0, 53, 1, 1, 0, 255];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(
            options,
            vec![Dhcpv4Option::MessageType(DhcpMessageType::Discover)]
        );
    }

    #[test]
    fn parse_stops_at_end_option() {
        let buf = [53, 1, 1, 255, 50, 4, 192, 168, 0, 10];

        let options = Dhcpv4Option::parse(&buf).unwrap();

        assert_eq!(
            options,
            vec![Dhcpv4Option::MessageType(DhcpMessageType::Discover)]
        );
    }

    #[test]
    fn parse_returns_invalid_message_type() {
        let buf = [53, 1, 99, 255];

        let err = Dhcpv4Option::parse(&buf).unwrap_err();

        assert_eq!(err, Dhcpv4Error::InvalidMessageType(99));
    }

    #[test]
    fn parse_returns_invalid_option_length_for_message_type() {
        let buf = [53, 2, 1, 2, 255];

        let err = Dhcpv4Option::parse(&buf).unwrap_err();

        assert_eq!(err, Dhcpv4Error::InvalidOptionLength(53));
    }

    #[test]
    fn parse_returns_invalid_option_length_for_requested_ip() {
        let buf = [50, 3, 192, 168, 0, 255];

        let err = Dhcpv4Option::parse(&buf).unwrap_err();

        assert_eq!(err, Dhcpv4Error::InvalidOptionLength(50));
    }

    #[test]
    fn parse_returns_wire_error_on_truncated_option_length() {
        let buf = [53];

        let err = Dhcpv4Option::parse(&buf).unwrap_err();

        assert!(matches!(err, Dhcpv4Error::Wire(_)));
    }

    #[test]
    fn parse_returns_wire_error_on_truncated_option_value() {
        let buf = [54, 4, 192, 168];

        let err = Dhcpv4Option::parse(&buf).unwrap_err();

        assert!(matches!(err, Dhcpv4Error::Wire(_)));
    }
}
