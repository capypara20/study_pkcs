//! 署名・検証。
//!
//! cryptoki では C_SignInit + C_Sign が [`Session::sign`] の 1 メソッドに、
//! C_VerifyInit + C_Verify が [`Session::verify`] に合体している。
//!
//! ここでは RSA 秘密鍵で SHA256+RSA-PKCS 署名する例。EC 鍵で署名したい場合は
//! メカニズムを `Mechanism::EcdsaSha256` に変えるだけ。

use cryptoki::mechanism::Mechanism;
use cryptoki::object::ObjectClass;
use cryptoki::session::Session;

use crate::Result;
use crate::session::find_key;

/// ラベルで秘密鍵を探し、メッセージに署名する（= C_SignInit + C_Sign）。
pub fn sign(session: &Session, key_label: &str, message: &[u8]) -> Result<Vec<u8>> {
    let private_key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let signature = session.sign(&Mechanism::Sha256RsaPkcs, private_key, message)?;
    Ok(signature)
}

/// ラベルで公開鍵を探し、署名を検証する（= C_VerifyInit + C_Verify）。
///
/// 検証成功なら `Ok(())`、失敗なら `Err`。
pub fn verify(session: &Session, key_label: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    let public_key = find_key(session, key_label, ObjectClass::PUBLIC_KEY)?;
    session.verify(&Mechanism::Sha256RsaPkcs, public_key, message, signature)?;
    Ok(())
}
