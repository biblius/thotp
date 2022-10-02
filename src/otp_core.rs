//! Contains core functionality for generating OTPs

use super::ThotpError;
use digest::{
    block_buffer::Eager,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    crypto_common::BlockSizeUser,
    typenum::{IsLess, Le, NonZero, U256},
    FixedOutput, HashMarker, InvalidLength, Update,
};
use hmac::{Hmac, Mac};
use std::time::{SystemTime, UNIX_EPOCH};

/// The default digits for OTP generation
pub(super) const DIGITS_DEFAULT: u8 = 6;

/// The default and RFC recommended time step used to divide the duration in seconds from now
/// until the unix epoch.
pub(super) const TIME_STEP: u8 = 30;

/// Used by the verification functions as an offset to accept passwords from the previoues and next
/// time steps valid.
pub(super) const ALLOWED_DRIFT: u8 = 1;

/// Generates a MAC of the secret key and nonce, hashed with the provided algorithm.
#[inline]
pub(super) fn hmac_digest<H>(secret: &[u8], nonce: &[u8]) -> Result<Vec<u8>, InvalidLength>
where
    H: Update + FixedOutput + CoreProxy,
    H::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut mac = Hmac::<H>::new_from_slice(secret)?;
    <Hmac<H> as Update>::update(&mut mac, nonce);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// The dynamic truncate function as described in [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226).
/// Determines an offset based on the last 4 bits of the input. The offset is then used as the starting index
/// of a slice of the input that spans 4 bytes. Finally, that slice is returned with the first bit masked to 0
/// resulting in a sequence of 31 bits. This function returns those 4 bytes in an u32, mitigating the need to
/// call the function str_to_num since it basically happens when we transform the byte array to an integer.
#[inline]
pub(super) fn dynamic_trunc(input: &mut [u8]) -> u32 {
    // Grab the last 4 bits
    let offset = (input.last().unwrap() & 0xf) as usize;

    // Take a slice from the original bytes based on the offset
    let mut result: [u8; 4] = input[offset..=offset + 3].try_into().unwrap();

    // Mask the 32nd bit
    result[0] &= 0x7f;

    u32::from_be_bytes(result)
}

/// Calculates the number of seconds passed from the unix epoch divided by the default timestep.
#[inline]
pub(super) fn time_step_now() -> Result<u64, ThotpError> {
    let time_step = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / TIME_STEP as u64;
    Ok(time_step)
}

#[cfg(test)]
mod tests {
    use super::super::custom::{Sha1, Sha256, Sha512};
    use super::super::ThotpError;
    use super::*;
    #[test]
    fn hmac() -> Result<(), ThotpError> {
        let hmac = super::hmac_digest::<Sha1>(b"12345678901234567890", b"1")?;
        assert!(hmac.len() == 20);

        let hmac = super::hmac_digest::<Sha256>(b"12345678901234567890123456789012", b"1")?;
        assert!(hmac.len() == 32);

        let hmac = super::hmac_digest::<Sha512>(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            b"1",
        )?;
        assert!(hmac.len() == 64);
        Ok(())
    }

    #[test]
    fn dynamic_trunc_() -> Result<(), ThotpError> {
        let mut hmac = super::hmac_digest::<Sha1>(b"super secret key", b"1")?;
        assert_eq!(
            hmac,
            [
                104, 105, 130, 165, 155, 87, 155, 213, 180, 67, 104, 223, 123, 179, 211, 125, 173,
                78, 220, 226
            ]
        );

        // We know the last 4 bits will be taken as the offset
        let mask = 226 & 0x0f;
        assert_eq!(mask, 2);

        // Based on the offset we know the slice will be [130, 165, 155, 87]
        let res = dynamic_trunc(&mut hmac);

        // We also know the first bit will be masked, which in this case is the first bit of 130
        // and this will transform 130 to 2, the rest are hex representations of 165, 155 and 87
        assert_eq!(res, 0x02_a5_9b_57);
        Ok(())
    }
}
