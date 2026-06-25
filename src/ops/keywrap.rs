//! 鍵のラップ・アンラップ・導出。
//!
//! - **wrap**   … 鍵を別の鍵で暗号化して取り出す（安全なバックアップ・移送）
//! - **unwrap** … ラップされたバイト列を鍵として取り込む
//! - **derive** … 既存鍵から新しい鍵を導出（ECDH 鍵共有）
//!
//! HSM 運用の要となる機能。秘密鍵そのものは出さず、暗号化された形でのみ持ち出す。

use cryptoki::mechanism::elliptic_curve::{Ecdh1DeriveParams, EcKdf};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

use crate::Result;
use crate::session::find_key;

/// AES 鍵で別の AES 鍵をラップする（= C_WrapKey、CKM_AES_KEY_WRAP_PAD）。
///
/// `wrapping_label` の鍵は `Wrap=true`、`target_label` の鍵は `Extractable=true`
/// である必要がある。戻り値はラップ済みバイト列。
pub fn wrap(session: &Session, wrapping_label: &str, target_label: &str) -> Result<Vec<u8>> {
    let wrapping_key = find_key(session, wrapping_label, ObjectClass::SECRET_KEY)?;
    let target_key = find_key(session, target_label, ObjectClass::SECRET_KEY)?;
    let wrapped = session.wrap_key(&Mechanism::AesKeyWrapPad, wrapping_key, target_key)?;
    Ok(wrapped)
}

/// ラップ済みバイト列を AES 鍵として取り込む（= C_UnwrapKey）。
pub fn unwrap(
    session: &Session,
    unwrapping_label: &str,
    wrapped: &[u8],
    new_label: &str,
) -> Result<ObjectHandle> {
    let unwrapping_key = find_key(session, unwrapping_label, ObjectClass::SECRET_KEY)?;
    let template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Label(new_label.as_bytes().to_vec()),
    ];
    let key = session.unwrap_key(&Mechanism::AesKeyWrapPad, unwrapping_key, wrapped, &template)?;
    Ok(key)
}

/// ECDH で共有 AES 鍵を導出する（= C_DeriveKey、CKM_ECDH1_DERIVE）。
///
/// 自分の EC 秘密鍵(`priv_label`)と、相手の EC 公開鍵(`peer_pub_label`)から
/// 共有秘密を計算し、新しい AES 鍵を生成する。
pub fn derive_ecdh(
    session: &Session,
    priv_label: &str,
    peer_pub_label: &str,
    new_label: &str,
) -> Result<ObjectHandle> {
    let my_priv = find_key(session, priv_label, ObjectClass::PRIVATE_KEY)?;
    let peer_pub = find_key(session, peer_pub_label, ObjectClass::PUBLIC_KEY)?;

    // 相手の公開鍵の EC ポイントを取り出す（= C_GetAttributeValue）
    let attrs = session.get_attributes(peer_pub, &[AttributeType::EcPoint])?;
    let peer_point = attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(p) => Some(p),
            _ => None,
        })
        .ok_or("相手公開鍵から EcPoint を取得できませんでした")?;

    let params = Ecdh1DeriveParams::new(EcKdf::null(), &peer_point);
    let template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Token(true),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Label(new_label.as_bytes().to_vec()),
    ];
    let key = session.derive_key(&Mechanism::Ecdh1Derive(params), my_priv, &template)?;
    Ok(key)
}
