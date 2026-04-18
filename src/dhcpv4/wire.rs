use crate::wire;

// This file defines the structure of a DHCPv4 message as per RFC 2131.
// https://datatracker.ietf.org/doc/html/rfc2131#section-2
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
// +---------------+---------------+---------------+---------------+
// |                            xid (4)                            |
// +-------------------------------+-------------------------------+
// |           secs (2)            |           flags (2)           |
// +-------------------------------+-------------------------------+
// |                          ciaddr  (4)                          |
// +---------------------------------------------------------------+
// |                          yiaddr  (4)                          |
// +---------------------------------------------------------------+
// |                          siaddr  (4)                          |
// +---------------------------------------------------------------+
// |                          giaddr  (4)                          |
// +---------------------------------------------------------------+
// |                                                               |
// |                          chaddr  (16)                         |
// |                                                               |
// |                                                               |
// +---------------------------------------------------------------+
// |                                                               |
// |                          sname   (64)                         |
// +---------------------------------------------------------------+
// |                                                               |
// |                          file    (128)                        |
// +---------------------------------------------------------------+
// |                                                               |
// |                          options (variable)                   |
// +---------------------------------------------------------------+
//                Figure 1:  Format of a DHCP message

#[derive(Debug, PartialEq, Eq)]
pub struct Dhcpv4Wire<'a> {
    pub op: u8,
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
    pub options: &'a [u8],
}

impl<'a> Dhcpv4Wire<'a> {
    pub fn decode(buf: &'a [u8]) -> Result<Self, wire::Error> {
        let mut reader = wire::Reader::new(buf);

        Ok(Self {
            op: reader.read_u8()?,
            htype: reader.read_u8()?,
            hlen: reader.read_u8()?,
            hops: reader.read_u8()?,
            xid: reader.read_u32_be()?,
            secs: reader.read_u16_be()?,
            flags: reader.read_u16_be()?,
            ciaddr: reader.read_array::<4>()?,
            yiaddr: reader.read_array::<4>()?,
            siaddr: reader.read_array::<4>()?,
            giaddr: reader.read_array::<4>()?,
            chaddr: reader.read_array::<16>()?,
            sname: reader.read_array::<64>()?,
            file: reader.read_array::<128>()?,
            options: &buf[reader.position()..],
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = wire::Writer::with_capacity(236 + self.options.len());

        writer.write_u8(self.op);
        writer.write_u8(self.htype);
        writer.write_u8(self.hlen);
        writer.write_u8(self.hops);
        writer.write_u32_be(self.xid);
        writer.write_u16_be(self.secs);
        writer.write_u16_be(self.flags);
        writer.write_array(&self.ciaddr);
        writer.write_array(&self.yiaddr);
        writer.write_array(&self.siaddr);
        writer.write_array(&self.giaddr);
        writer.write_array(&self.chaddr);
        writer.write_array(&self.sname);
        writer.write_array(&self.file);
        writer.write_slice(self.options);
        writer.into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::Dhcpv4Wire;
    use crate::wire::Error;

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
    fn encode_writes_fixed_header_and_options() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 1, 255];
        let msg = sample_wire(options);

        let buf = msg.encode();

        assert_eq!(buf.len(), 236 + options.len());

        assert_eq!(buf[0], 1);
        assert_eq!(buf[1], 1);
        assert_eq!(buf[2], 6);
        assert_eq!(buf[3], 0);

        assert_eq!(&buf[4..8], &[0x39, 0x03, 0xf3, 0x26]);
        assert_eq!(&buf[8..10], &[0x00, 0x03]);
        assert_eq!(&buf[10..12], &[0x80, 0x00]);

        assert_eq!(&buf[12..16], &[0, 0, 0, 0]);
        assert_eq!(&buf[16..20], &[192, 168, 0, 10]);
        assert_eq!(&buf[20..24], &[192, 168, 0, 1]);
        assert_eq!(&buf[24..28], &[0, 0, 0, 0]);

        assert_eq!(
            &buf[28..44],
            &[
                0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
        );

        assert_eq!(&buf[44..108], &[0u8; 64]);
        assert_eq!(&buf[108..236], &[0u8; 128]);
        assert_eq!(&buf[236..], options);
    }

    #[test]
    fn decode_reads_fixed_header_and_options() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 1, 255];
        let original = sample_wire(options);
        let buf = original.encode();

        let decoded = Dhcpv4Wire::decode(&buf).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_returns_unexpected_eof_for_short_buffer() {
        let buf = [0u8; 235];

        let err = Dhcpv4Wire::decode(&buf).unwrap_err();

        assert_eq!(
            err,
            Error::UnexpectedEof {
                position: 108,
                needed: 128,
                remaining: 127,
            }
        );
    }

    #[test]
    fn round_trip_preserves_bytes() {
        let options = &[0x63, 0x82, 0x53, 0x63, 53, 1, 1, 55, 3, 1, 3, 6, 255];
        let original = sample_wire(options);

        let encoded = original.encode();
        let decoded = Dhcpv4Wire::decode(&encoded).unwrap();
        let reencoded = decoded.encode();

        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn decode_accepts_empty_options() {
        let msg = sample_wire(&[]);
        let buf = msg.encode();

        let decoded = Dhcpv4Wire::decode(&buf).unwrap();

        assert_eq!(decoded.options, &[]);
        assert_eq!(decoded, msg);
    }
}
