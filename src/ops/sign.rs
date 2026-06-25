//! 署名・検証。
//!
//! cryptoki では C_SignInit + C_Sign が [`Session::sign`] の 1 メソッドに、
//! C_VerifyInit + C_Verify が [`Session::verify`] に合体している。
//!
//! 鍵の種類(RSA/EC/Ed25519)で使うべきメカニズムが変わるので、
//! ここでは鍵の `KeyType` を読み取って **自動でメカニズムを選ぶ**。
//! これで「keygen で作った鍵 → そのまま sign」が種類を問わず通る。

use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

use crate::Result;
use crate::session::find_key;

/// 鍵の種類から適切な署名メカニズムを決める。
///
/// - RSA        → `Sha256RsaPkcs`（SHA-256 でハッシュして RSA 署名）
/// - EC         → `EcdsaSha256`（SHA-256 + ECDSA）
/// - Ed25519    → `Eddsa`（EdDSA。内部でハッシュ込み）
fn mechanism_for(session: &Session, key: ObjectHandle) -> Result<Mechanism<'_>> {
    let attrs = session.get_attributes(key, &[AttributeType::KeyType])?;
    let key_type = attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::KeyType(k) => Some(k),
            _ => None,
        })
        .ok_or("鍵の KeyType を取得できませんでした")?;

    let mech = match key_type {
        KeyType::RSA => Mechanism::Sha256RsaPkcs,
        KeyType::EC => Mechanism::EcdsaSha256,
        KeyType::EC_EDWARDS => Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
        other => return Err(format!("署名に未対応の鍵種別です: {other:?}").into()),
    };
    Ok(mech)
}

/// ラベルで秘密鍵を探し、メッセージに署名する（= C_SignInit + C_Sign）。
///
/// 鍵種別に応じてメカニズムを自動選択する。
pub fn sign(session: &Session, key_label: &str, message: &[u8]) -> Result<Vec<u8>> {
    let private_key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let mech = mechanism_for(session, private_key)?;
    let signature = session.sign(&mech, private_key, message)?;
    Ok(signature)
}

/// ラベルで公開鍵を探し、署名を検証する（= C_VerifyInit + C_Verify）。
///
/// 検証成功なら `Ok(())`、失敗なら `Err`。
pub fn verify(session: &Session, key_label: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    let public_key = find_key(session, key_label, ObjectClass::PUBLIC_KEY)?;
    let mech = mechanism_for(session, public_key)?;
    session.verify(&mech, public_key, message, signature)?;
    Ok(())
}
