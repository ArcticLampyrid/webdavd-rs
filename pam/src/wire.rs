// Serialization of the messages exchanged between the PAM client
// and the PAM server process.
//
// This uses rkyv, which archives the messages in place: the bytes are
// validated with bytecheck when they come back off the socket, and are
// then deserialized into the original types.
use rkyv::api::high::{HighSerializer, HighValidator};
use rkyv::bytecheck::CheckBytes;
use rkyv::de::Pool;
use rkyv::rancor::{self, Strategy};
use rkyv::ser::allocator::ArenaHandle;
use rkyv::util::AlignedVec;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

pub(crate) type EncodeError = rancor::Error;
pub(crate) type DecodeError = rancor::Error;

pub(crate) fn serialize<T>(value: &T) -> Result<AlignedVec, EncodeError>
where T: for<'a> RkyvSerialize<HighSerializer<AlignedVec, ArenaHandle<'a>, EncodeError>> {
    rkyv::to_bytes::<EncodeError>(value)
}

pub(crate) fn deserialize<T>(data: &[u8]) -> Result<T, DecodeError>
where
    T: Archive,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, DecodeError>>,
    T::Archived: RkyvDeserialize<T, Strategy<Pool, DecodeError>>,
{
    // rkyv requires the buffer to be aligned for `T::Archived`, but callers
    // hand us arbitrary byte slices (e.g. read straight off a socket), so
    // copy the data into an aligned buffer first.
    let mut aligned = AlignedVec::<16>::with_capacity(data.len());
    aligned.extend_from_slice(data);
    rkyv::from_bytes::<T, DecodeError>(&aligned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pam::{PamError, ERR_NUL_BYTE, ERR_RECV_FROM_SERVER, ERR_SEND_TO_SERVER};
    use crate::pamclient::PamRequest;
    use crate::pamserver::PamResponse;

    fn request(remip: Option<&str>) -> PamRequest {
        PamRequest {
            id:      0x0102030405060708,
            user:    "user".to_string(),
            pass:    "pass".to_string(),
            service: "other".to_string(),
            remip:   remip.map(str::to_string),
        }
    }

    #[test]
    fn request_roundtrip() {
        for remip in [None, Some(""), Some("127.0.0.1")] {
            let req = request(remip);
            let data = serialize(&req).unwrap();
            let back: PamRequest = deserialize(&data).unwrap();
            assert_eq!(back, req);
        }
    }

    #[test]
    fn response_roundtrip() {
        let ok = PamResponse {
            id:     1,
            result: Ok(()),
        };
        let data = serialize(&ok).unwrap();
        let back: PamResponse = deserialize(&data).unwrap();
        assert_eq!(back, ok);

        for err in [
            PamError(7),
            PamError(ERR_NUL_BYTE),
            PamError(ERR_SEND_TO_SERVER),
            PamError(ERR_RECV_FROM_SERVER),
            PamError::unknown(),
        ] {
            let resp = PamResponse {
                id:     2,
                result: Err(err.clone()),
            };
            let data = serialize(&resp).unwrap();
            let back: PamResponse = deserialize(&data).unwrap();
            assert_eq!(back, resp);
        }
    }

    #[test]
    fn deserialize_unaligned_slice() {
        let req = request(Some("127.0.0.1"));
        let data = serialize(&req).unwrap();

        // prepend a dummy byte, so the payload does not start at an address
        // aligned for `ArchivedPamRequest`.
        let mut unaligned = vec![0u8];
        unaligned.extend_from_slice(&data);
        let payload = &unaligned[1..];
        assert_ne!(
            payload.as_ptr() as usize % std::mem::align_of::<<PamRequest as Archive>::Archived>(),
            0
        );
        let back: PamRequest = deserialize(payload).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn deserialize_malformed() {
        // empty and too-short buffers.
        assert!(deserialize::<PamRequest>(&[]).is_err());
        assert!(deserialize::<PamRequest>(&[0u8; 4]).is_err());
        assert!(deserialize::<PamResponse>(&[0xffu8; 8]).is_err());

        // truncated valid data.
        let req = request(None);
        let data = serialize(&req).unwrap();
        assert!(deserialize::<PamRequest>(&data[..data.len() / 2]).is_err());
        assert!(deserialize::<PamRequest>(&data[..data.len() - 1]).is_err());
    }
}
