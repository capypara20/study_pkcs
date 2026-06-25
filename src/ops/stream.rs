//! 分割処理（マルチパート、Init → Update×N → Final）。
//!
//! 大きなデータを一度にメモリへ載せず、チャンク単位で投入する方式。
//! cryptoki でも一発版とは別に `*_init` / `*_update` / `*_final` が用意されている。
//!
//! ここでは仕組みを見せるため、わざと小さなチャンク(16 バイト)に区切って投入する。

use cryptoki::mechanism::Mechanism;
use cryptoki::object::ObjectClass;
use cryptoki::session::Session;

use crate::Result;
use crate::session::find_key;

/// 1 チャンクのバイト数（デモ用）。
const CHUNK: usize = 16;

/// データを分割しながら SHA-256 でハッシュする
/// （= C_DigestInit + C_DigestUpdate×N + C_DigestFinal）。
pub fn digest_sha256(session: &Session, data: &[u8]) -> Result<Vec<u8>> {
    session.digest_init(&Mechanism::Sha256)?;
    for chunk in data.chunks(CHUNK) {
        session.digest_update(chunk)?;
    }
    let hash = session.digest_final()?;
    Ok(hash)
}

/// データを分割しながら署名する
/// （= C_SignInit + C_SignUpdate×N + C_SignFinal）。
pub fn sign(session: &Session, key_label: &str, data: &[u8]) -> Result<Vec<u8>> {
    let key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    session.sign_init(&Mechanism::Sha256RsaPkcs, key)?;
    for chunk in data.chunks(CHUNK) {
        session.sign_update(chunk)?;
    }
    let signature = session.sign_final()?;
    Ok(signature)
}

/// データを分割しながら署名検証する
/// （= C_VerifyInit + C_VerifyUpdate×N + C_VerifyFinal）。
pub fn verify(session: &Session, key_label: &str, data: &[u8], signature: &[u8]) -> Result<()> {
    let key = find_key(session, key_label, ObjectClass::PUBLIC_KEY)?;
    session.verify_init(&Mechanism::Sha256RsaPkcs, key)?;
    for chunk in data.chunks(CHUNK) {
        session.verify_update(chunk)?;
    }
    session.verify_final(signature)?;
    Ok(())
}
