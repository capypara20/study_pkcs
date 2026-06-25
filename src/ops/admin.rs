//! トークン・PIN 管理（管理者向け・破壊的操作を含む）。
//!
//! ⚠️ `init_token` はトークンの中身を**全消去**する。取り扱い注意。

use cryptoki::context::Pkcs11;
use cryptoki::session::Session;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::Result;

/// トークンを初期化する（= C_InitToken）。SO-PIN とラベルを設定。
///
/// ⚠️ 既存の鍵・データは消える。
pub fn init_token(pkcs11: &Pkcs11, slot: Slot, so_pin: &str, label: &str) -> Result<()> {
    pkcs11.init_token(slot, &AuthPin::new(so_pin.to_string()), label)?;
    Ok(())
}

/// ユーザ PIN を初期設定する（= C_InitPIN）。SO でログイン済みのセッションで実行。
pub fn init_pin(session: &Session, new_pin: &str) -> Result<()> {
    session.init_pin(&AuthPin::new(new_pin.to_string()))?;
    Ok(())
}

/// PIN を変更する（= C_SetPIN）。
pub fn set_pin(session: &Session, old_pin: &str, new_pin: &str) -> Result<()> {
    session.set_pin(
        &AuthPin::new(old_pin.to_string()),
        &AuthPin::new(new_pin.to_string()),
    )?;
    Ok(())
}
