//! 鍵生成 ＝ RSA / EC（非対称・ペア生成）と AES（対称・単数生成）。
//!
//! 覚え方:
//! - 非対称鍵 → [`Session::generate_key_pair`]（公開・秘密の 2 テンプレ）
//! - 対称鍵   → [`Session::generate_key`]（テンプレ 1 つ）
//!
//! テンプレ(属性)で「その鍵に何を許すか」を決める。とくに
//! `Sensitive(true)` + `Extractable(false)` が「鍵を外に出さない」HSM の肝。

use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::Session;

use crate::Result;

/// RSA 鍵ペアを HSM 内で生成する（= C_GenerateKeyPair）。
///
/// 戻り値は `(公開鍵ハンドル, 秘密鍵ハンドル)`。
pub fn rsa(session: &Session, bits: u64, label: &str) -> Result<(ObjectHandle, ObjectHandle)> {
    let pub_template = vec![
        Attribute::Token(true),                          // トークンに永続保存
        Attribute::Verify(true),                         // 検証に使える
        Attribute::Encrypt(true),                        // 暗号化に使える
        Attribute::ModulusBits(bits.into()),             // 鍵長(2048 等)
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]), // 65537
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),       // 署名に使える
        Attribute::Decrypt(true),    // 復号に使える
        Attribute::Sensitive(true),  // 値を読み出せない
        Attribute::Extractable(false), // 持ち出し禁止 ← HSM の肝
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let keys = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &pub_template,
        &priv_template,
    )?;
    Ok(keys)
}

/// EC(P-256 / secp256r1) 鍵ペアを生成する（= C_GenerateKeyPair）。
///
/// RSA の `ModulusBits` の代わりに、曲線を DER エンコードした OID を
/// `EcParams` で渡すのがポイント。
pub fn ec(session: &Session, label: &str) -> Result<(ObjectHandle, ObjectHandle)> {
    // OID 1.2.840.10045.3.1.7 (prime256v1 / NIST P-256) の DER 表現
    let ec_params = vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::EcParams(ec_params), // ← 曲線指定
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let keys = session.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &pub_template,
        &priv_template,
    )?;
    Ok(keys)
}

/// AES 共通鍵を生成する（= C_GenerateKey）。
///
/// `bytes` は鍵長(バイト): 16=AES-128, 24=AES-192, 32=AES-256。
pub fn aes(session: &Session, bytes: u64, label: &str) -> Result<ObjectHandle> {
    let template = vec![
        Attribute::Token(true),
        Attribute::ValueLen(bytes.into()), // 鍵長(バイト数)
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let key = session.generate_key(&Mechanism::AesKeyGen, &template)?;
    Ok(key)
}
