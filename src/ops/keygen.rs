//! 鍵生成 ＝ 各種アルゴリズムの鍵を HSM 内で作る。
//!
//! 大きく 2 系統:
//! - **非対称鍵(鍵ペア)** … RSA / EC / Ed25519 / X25519。[`Session::generate_key_pair`]（公開・秘密の 2 テンプレ）
//! - **対称鍵(単一鍵)**   … AES / Generic-Secret(HMAC用)。[`Session::generate_key`]（テンプレ 1 つ）
//!
//! 鍵生成で決めるのは常に 2 つ:
//! 1. **メカニズム** … どのアルゴリズムで作るか（`Mechanism::*KeyPairGen` / `*KeyGen`）
//! 2. **テンプレート(属性の配列)** … その鍵に何を許すか（署名可・持出禁止 等）
//!
//! とくに `Sensitive(true)` + `Extractable(false)` が「鍵を外に出さない」HSM の肝。

use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::Session;

use crate::Result;

/// RSA 鍵ペアを生成する（= C_GenerateKeyPair, CKM_RSA_PKCS_KEY_PAIR_GEN）。
///
/// 鍵長は `bits`（2048/3072/4096 など）。署名にも暗号にも使える設定にしている。
/// 戻り値は `(公開鍵ハンドル, 秘密鍵ハンドル)`。
pub fn rsa(session: &Session, bits: u64, label: &str) -> Result<(ObjectHandle, ObjectHandle)> {
    let pub_template = vec![
        Attribute::Token(true),                            // トークンに永続保存
        Attribute::Verify(true),                           // 署名検証に使える
        Attribute::Encrypt(true),                          // 暗号化に使える
        Attribute::ModulusBits(bits.into()),               // 鍵長(RSA 固有の指定)
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]), // 公開指数 65537
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),         // 署名に使える
        Attribute::Decrypt(true),      // 復号に使える
        Attribute::Sensitive(true),    // 値を読み出せない
        Attribute::Extractable(false), // 持ち出し禁止 ← HSM の肝
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let keys = session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_template, &priv_template)?;
    Ok(keys)
}

/// 既知の曲線名 → `EcParams`(OID を DER エンコードしたバイト列) を返す。
///
/// EC 鍵生成では RSA の `ModulusBits` の代わりに、この「曲線の OID」を渡して
/// どの楕円曲線かを指定する。
pub fn ec_curve_oid(name: &str) -> Option<Vec<u8>> {
    let oid: &[u8] = match name {
        // prime256v1 / secp256r1 / NIST P-256  (1.2.840.10045.3.1.7)
        "p256" | "prime256v1" | "secp256r1" => &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // secp384r1 / NIST P-384  (1.3.132.0.34)
        "p384" | "secp384r1" => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
        // secp521r1 / NIST P-521  (1.3.132.0.35)
        "p521" | "secp521r1" => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23],
        // secp256k1 (Bitcoin 等)  (1.3.132.0.10)
        "secp256k1" | "k256" => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A],
        _ => return None,
    };
    Some(oid.to_vec())
}

/// EC(ECDSA 用) 鍵ペアを生成する（= C_GenerateKeyPair, CKM_EC_KEY_PAIR_GEN）。
///
/// `curve` は [`ec_curve_oid`] が知る名前（"p256"/"p384"/"p521"/"secp256k1"）。
/// 署名は後で `Mechanism::EcdsaSha256` を使う。
pub fn ec(session: &Session, curve: &str, label: &str) -> Result<(ObjectHandle, ObjectHandle)> {
    let ec_params = ec_curve_oid(curve).ok_or_else(|| format!("未知の曲線: {curve}"))?;
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::EcParams(ec_params), // ← 曲線指定(RSA の ModulusBits 相当)
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
    let keys = session.generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)?;
    Ok(keys)
}

/// Ed25519 鍵ペアを生成する（= C_GenerateKeyPair, CKM_EC_EDWARDS_KEY_PAIR_GEN）。
///
/// 署名は後で `Mechanism::Eddsa`(EdDSA) を使う。`EcParams` には edwards25519 の
/// OID(1.3.101.112) を渡す（トークンによっては曲線名文字列を要求する場合もある）。
pub fn ed25519(session: &Session, label: &str) -> Result<(ObjectHandle, ObjectHandle)> {
    let ed_oid = vec![0x06, 0x03, 0x2B, 0x65, 0x70]; // 1.3.101.112
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::EcParams(ed_oid),
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
    let keys = session.generate_key_pair(&Mechanism::EccEdwardsKeyPairGen, &pub_template, &priv_template)?;
    Ok(keys)
}

/// X25519 鍵ペアを生成する（= C_GenerateKeyPair, CKM_EC_MONTGOMERY_KEY_PAIR_GEN）。
///
/// これは「署名用」ではなく「鍵共有(ECDH)用」。なので `Derive(true)` を付ける。
/// `EcParams` には curve25519 の OID(1.3.101.110) を渡す。
pub fn x25519(session: &Session, label: &str) -> Result<(ObjectHandle, ObjectHandle)> {
    let x_oid = vec![0x06, 0x03, 0x2B, 0x65, 0x6E]; // 1.3.101.110
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Derive(true), // 鍵共有(導出)に使う
        Attribute::EcParams(x_oid),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Derive(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let keys = session.generate_key_pair(&Mechanism::EccMontgomeryKeyPairGen, &pub_template, &priv_template)?;
    Ok(keys)
}

/// AES 共通鍵を生成する（= C_GenerateKey, CKM_AES_KEY_GEN）。
///
/// `bytes` は鍵長(バイト): 16=AES-128, 24=AES-192, 32=AES-256。
/// 鍵ラップにも使えるよう `Wrap`/`Unwrap` も許可している。
pub fn aes(session: &Session, bytes: u64, label: &str) -> Result<ObjectHandle> {
    let template = vec![
        Attribute::Token(true),
        Attribute::ValueLen(bytes.into()), // 鍵長(バイト数)。対称鍵はこれで長さ指定
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Wrap(true),   // 他の鍵をラップできる
        Attribute::Unwrap(true), // ラップされた鍵を取り込める
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let key = session.generate_key(&Mechanism::AesKeyGen, &template)?;
    Ok(key)
}

/// Generic-Secret 鍵を生成する（= C_GenerateKey, CKM_GENERIC_SECRET_KEY_GEN）。
///
/// HMAC など「ただのバイト列の秘密鍵」が要る用途向け。`bytes` は鍵長(バイト)。
pub fn generic_secret(session: &Session, bytes: u64, label: &str) -> Result<ObjectHandle> {
    let template = vec![
        Attribute::Token(true),
        Attribute::ValueLen(bytes.into()),
        Attribute::Sign(true),   // HMAC 生成
        Attribute::Verify(true), // HMAC 検証
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let key = session.generate_key(&Mechanism::GenericSecretKeyGen, &template)?;
    Ok(key)
}
