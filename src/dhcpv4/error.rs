use crate::wire;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dhcpv4Error {
    Wire(wire::Error),

    InvalidBootpOpCode(u8),

    InvalidMagicCookie,
    MissingMessageType,
    InvalidMessageType(u8),
    InvalidOptionFormat,
    InvalidOptionLength(u8),
    InvalidHardwareAddressLength(u8),
}

impl From<wire::Error> for Dhcpv4Error {
    fn from(err: wire::Error) -> Self {
        Self::Wire(err)
    }
}

impl core::fmt::Display for Dhcpv4Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "wire error: {}", e),
            Self::InvalidBootpOpCode(v) => write!(f, "invalid BOOTP op code: {}", v),
            Self::InvalidMagicCookie => write!(f, "invalid DHCP magic cookie"),
            Self::MissingMessageType => write!(f, "missing DHCP message type option"),
            Self::InvalidMessageType(t) => {
                write!(f, "invalid DHCP message type: {}", t)
            }
            Self::InvalidOptionFormat => write!(f, "invalid DHCP option format"),
            Self::InvalidOptionLength(l) => write!(f, "invalid DHCP option length: {}", l),
            Self::InvalidHardwareAddressLength(l) => {
                write!(f, "invalid hardware address length: {}", l)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Dhcpv4Error;
    use crate::wire;

    #[test]
    fn from_wire_error() {
        let wire_err = wire::Error::unexpected_eof(10, 4, 2);
        let err = Dhcpv4Error::from(wire_err);

        assert_eq!(err, Dhcpv4Error::Wire(wire_err));
    }

    #[test]
    fn display_wire_error() {
        let err = Dhcpv4Error::Wire(wire::Error::unexpected_eof(10, 4, 2));

        assert_eq!(
            err.to_string(),
            "wire error: unexpected EOF at position 10, needed 4 bytes, remaining 2 bytes"
        );
    }

    #[test]
    fn display_invalid_magic_cookie() {
        let err = Dhcpv4Error::InvalidMagicCookie;

        assert_eq!(err.to_string(), "invalid DHCP magic cookie");
    }

    #[test]
    fn display_missing_message_type() {
        let err = Dhcpv4Error::MissingMessageType;

        assert_eq!(err.to_string(), "missing DHCP message type option");
    }

    #[test]
    fn display_invalid_message_type() {
        let err = Dhcpv4Error::InvalidMessageType(99);

        assert_eq!(err.to_string(), "invalid DHCP message type: 99");
    }

    #[test]
    fn display_invalid_option_format() {
        let err = Dhcpv4Error::InvalidOptionFormat;

        assert_eq!(err.to_string(), "invalid DHCP option format");
    }
}
