// Serialization of the messages exchanged between the PAM client
// and the PAM server process.
//
// This uses bincode's "legacy" configuration (little-endian, fixed-size
// integers), which produces exactly the same encoding as bincode 1.x.
use serde::{de::DeserializeOwned, Serialize};

pub(crate) type EncodeError = bincode::error::EncodeError;
pub(crate) type DecodeError = bincode::error::DecodeError;

pub(crate) fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
}

pub(crate) fn deserialize<T: DeserializeOwned>(data: &[u8]) -> Result<T, DecodeError> {
    bincode::serde::decode_from_slice(data, bincode::config::legacy()).map(|(value, _len)| value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pam::PamError;
    use crate::pamclient::PamRequest;
    use crate::pamserver::PamResponse;

    #[test]
    fn request_encoding_matches_bincode1() {
        let req = PamRequest {
            id:      0x0102030405060708,
            user:    "ab".to_string(),
            pass:    "c".to_string(),
            service: "".to_string(),
            remip:   Some("d".to_string()),
        };
        let data = serialize(&req).unwrap();
        #[rustfmt::skip]
        let expected: &[u8] = &[
            8, 7, 6, 5, 4, 3, 2, 1,         // id: u64 LE
            2, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', // user: u64 len + bytes
            1, 0, 0, 0, 0, 0, 0, 0, b'c',   // pass
            0, 0, 0, 0, 0, 0, 0, 0,         // service (empty)
            1, 1, 0, 0, 0, 0, 0, 0, 0, b'd', // remip: Some tag + string
        ];
        assert_eq!(data, expected);
        let back: PamRequest = deserialize(&data).unwrap();
        assert_eq!(back.id, req.id);
        assert_eq!(back.user, req.user);
        assert_eq!(back.remip, req.remip);
    }

    #[test]
    fn response_encoding_matches_bincode1() {
        let ok = PamResponse { id: 1, result: Ok(()) };
        assert_eq!(serialize(&ok).unwrap(), [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let err = PamResponse { id: 2, result: Err(PamError(7)) };
        let data = serialize(&err).unwrap();
        assert_eq!(data, [2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0]);
        let back: PamResponse = deserialize(&data).unwrap();
        assert_eq!(back.result, Err(PamError(7)));
    }
}
