# THOTP

OTP implementations based on [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) for Hmac-based OTPs
and [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) for Time-based OTPs.

More docs on the [docs page].

## Example usage

```rust
use thotp::{
    otp,
    verify_totp,
    time_step_now,
    generate_secret,
    encoding::{encode, decode},
    qr::generate_code,
};

// Generate an encoded secret

let secret = generate_secret(80);
let encoded = encode(&secret, data_encoding::BASE32);
 
// Store the secret somewhere safe

let qr_code = generate_code(
    "totp",
    &encoded,
    "Big Corp:john.doe@email.com",
    "Big Corp",
    None,
    None,
    qrcode::EcLevel::M
)
.expect("uh oh");

// Scan qr with some authenticator app

// Verify a password provided from the client, assume this is what they calculated

let pw = otp(&secret, time_step_now());

let result = verify_totp(&pw, &secret, 0);

assert!(result);
```