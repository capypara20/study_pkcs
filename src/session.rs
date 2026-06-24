//! 接続・スロット選択・ログイン ＝ PKCS#11 の「会話の骨格」。
//!
//! 生 FFI で言うと、ここが
//!   C_GetFunctionList → C_Initialize → C_GetSlotList
//!   → C_OpenSession → C_Login
//! に相当する。`C_Finalize` / `C_CloseSession` / `C_Logout` は
//! cryptoki の `Pkcs11` / `Session` が破棄される時に自動で呼ばれるので、
//! ここでは書かなくてよい（Drop 任せ）。

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::Result;

/// `.so` をロードして初期化する（= C_GetFunctionList + C_Initialize）。
///
/// `CInitializeArgs::OsThreads` は「OS ネイティブのロックで
/// スレッドセーフに動かす(CKF_OS_LOCKING_OK)」という指定。
pub fn connect(lib_path: &str) -> Result<Pkcs11> {
    let pkcs11 = Pkcs11::new(lib_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    Ok(pkcs11)
}

/// トークン入りスロットを 1 つ選ぶ（= C_GetSlotList の結果から index 番目）。
pub fn pick_slot(pkcs11: &Pkcs11, index: Option<usize>) -> Result<Slot> {
    let slots = pkcs11.get_slots_with_token()?;
    let i = index.unwrap_or(0);
    slots
        .get(i)
        .copied()
        .ok_or_else(|| format!("トークン入りスロットが {i} 番目に見つかりません (全 {} 個)", slots.len()).into())
}

/// RW セッションを開いてログインする（= C_OpenSession + C_Login）。
pub fn login_rw(pkcs11: &Pkcs11, slot: Slot, pin: &str) -> Result<Session> {
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(pin.to_string())))?;
    Ok(session)
}

/// ラベルとオブジェクトクラスで鍵を 1 つ探す（= C_FindObjectsInit/Find/Final）。
///
/// `class` には [`ObjectClass::PRIVATE_KEY`] / [`ObjectClass::PUBLIC_KEY`] /
/// [`ObjectClass::SECRET_KEY`] などを渡す。
pub fn find_key(session: &Session, label: &str, class: ObjectClass) -> Result<ObjectHandle> {
    let template = vec![
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(class),
    ];
    let found = session.find_objects(&template)?;
    found
        .into_iter()
        .next()
        .ok_or_else(|| format!("ラベル '{label}' の鍵(class={class:?}) が見つかりません").into())
}
