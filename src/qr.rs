//! Contains a function to generate a qr code ready to be scanned by an authenticator app.

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
pub use qrcode::EcLevel;
use qrcode::{self, render::svg::Color, types::QrError, QrCode};

/// Generates an otp uri following [this specification](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
/// The `otp_type` must be either `"totp"` or `"hotp"`.
fn generate_otp_uri(otp_type: &str, secret: &str, label: &str, issuer: &str) -> String {
    if otp_type != "totp" && otp_type != "hotp" {
        panic!("Invalid otp type provided")
    }
    let label = utf8_percent_encode(label, NON_ALPHANUMERIC);
    let issuer = utf8_percent_encode(issuer, NON_ALPHANUMERIC);
    format!(
        "otpauth://{}/{}?secret={}&issuer={}",
        otp_type, label, secret, issuer
    )
}

/// Generates a QR code SVG ready to be scanned by an authenticator app.
///
/// The `otp_type` must be either be `"totp"` or `"hotp"` or the function will return an error.
///
/// The `secret` is what gets appended to the otp uri as described
/// [here](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) along with `label` and `issuer`.
///
/// The `width` and `height` parameters are used to adjust the size of the
/// generated SVG and if not provided default to 200.
///
/// The `ec_level` indicates how much wrong blocks are allowed in the generated QR code.
pub fn generate_code(
    otp_type: &str,
    secret: &str,
    label: &str,
    issuer: &str,
    width: Option<u32>,
    height: Option<u32>,
    ec_level: EcLevel,
) -> Result<String, QrError> {
    let width = if let Some(width) = width { width } else { 0 };
    let height = if let Some(height) = height { height } else { 0 };
    let uri = generate_otp_uri(otp_type, secret, label, issuer);
    let code = QrCode::with_error_correction_level(uri, ec_level)?;
    Ok(code
        .render()
        .min_dimensions(width, height)
        .dark_color(Color("#000000"))
        .light_color(Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{
        encoding::{decode, encode},
        generate_secret, otp, TIME_STEP,
    };

    // These tests don't assert anything, but are useful for debugging qr codes and codes from
    // the authenticator
    #[test]
    fn qr() {
        let secret = generate_secret(80);
        let secret = &encode(&secret, data_encoding::BASE32);
        let _code = generate_code(
            "hotp",
            secret,
            "biblius",
            "bedgalopolis",
            Some(400),
            Some(400),
            EcLevel::H,
        )
        .unwrap();
        // std::fs::write("./temp_secret", secret).unwrap();
        // std::fs::write("./qr.html", _code).unwrap();
    }

    // Used to check the current time totp, useful to compare to https://totp.danhersam.com/
    #[test]
    fn totp_now() {
        let secret = "XNIOCRY5QWDXAUIQ7MN4CMNDY3RVZOFIWAPCZI5OQAYCD7SUZEJL6JTLV7BQPVRD2P2S65USD5XOEGQXMWI4NRJ3C2LLVHYHOWIOPLCYO74YQNCSGSW4MBEQRV3BER3K";
        let secret = decode(secret, data_encoding::BASE32);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / TIME_STEP as u64;
        let _totp = otp(&secret, nonce);
        // println!("TOTP: {}", _totp);
        // let _res = verify_totp("789705", &secret, 0);
    }

    #[test]
    fn hotp_now() {
        let secret = "ACTGTGXN6K5SIAWMTDPAUULYEZI2RFA3NFJC27U4EO4PNL6UEMUB3ZOD7BGOIRAFF54RDGBAKAZKTCX2CDRLPQ3GPW42AXVD4SEKLWNTBM56O4EXP7HUBBGKEEUHM4IF";
        let secret = decode(secret, data_encoding::BASE32);
        let nonce = 3;
        let _totp = otp(&secret, nonce);
        // println!("HOTP: {}", _totp);
        // let _res = verify_totp("789705", &secret, 0);
    }
}
