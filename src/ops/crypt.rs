//! 暗号化・復号（AES-CBC + パディング）。
//!
//! C_EncryptInit + C_Encrypt が [`Session::encrypt`] に、
//! C_DecryptInit + C_Decrypt が [`Session::decrypt`] に合体している。
//!
//! 注意: ここではデモのため IV を固定(全 0)にしている。実運用では
//! IV は毎回ランダムにし、暗号文と一緒に保存・送信すること。

use cryptoki::mechanism::Mechanism;
use cryptoki::object::ObjectClass;
use cryptoki::session::Session;

use crate::Result;
use crate::session::find_key;

/// デモ用の固定 IV（実運用では使わないこと）。
const DEMO_IV: [u8; 16] = [0u8; 16];

/// ラベルで AES 鍵を探し、平文を暗号化する（= C_EncryptInit + C_Encrypt）。
pub fn encrypt(session: &Session, key_label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = find_key(session, key_label, ObjectClass::SECRET_KEY)?;
    let ciphertext = session.encrypt(&Mechanism::AesCbcPad(DEMO_IV), key, plaintext)?;
    Ok(ciphertext)
}

/// ラベルで AES 鍵を探し、暗号文を復号する（= C_DecryptInit + C_Decrypt）。
pub fn decrypt(session: &Session, key_label: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = find_key(session, key_label, ObjectClass::SECRET_KEY)?;
    let plaintext = session.decrypt(&Mechanism::AesCbcPad(DEMO_IV), key, ciphertext)?;
    Ok(plaintext)
}
