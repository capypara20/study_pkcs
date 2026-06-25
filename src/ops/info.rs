//! Utility 系 ＝ 取得系コマンド。
//!
//! ログイン不要・Init/Final 不要なので、「ちゃんと HSM に繋がったか」を
//! 最初に確認するのに最適。

use cryptoki::context::Pkcs11;
use cryptoki::session::Session;
use cryptoki::slot::Slot;

use crate::Result;

/// ライブラリ → 各スロット → 各トークン → 対応メカニズムの順に情報を出す。
///
/// 対応する C API:
/// - `C_GetInfo`          → [`Pkcs11::get_library_info`]
/// - `C_GetSlotList`      → [`Pkcs11::get_slots_with_token`]
/// - `C_GetSlotInfo`      → [`Pkcs11::get_slot_info`]
/// - `C_GetTokenInfo`     → [`Pkcs11::get_token_info`]
/// - `C_GetMechanismList` → [`Pkcs11::get_mechanism_list`]
pub fn show(pkcs11: &Pkcs11) -> Result<()> {
    // --- ① ライブラリ情報（C_GetInfo）---
    let info = pkcs11.get_library_info()?;
    let cv = info.cryptoki_version();
    let lv = info.library_version();
    println!("=== ライブラリ情報 (C_GetInfo) ===");
    println!("  Cryptoki 仕様版 : {}.{}", cv.major(), cv.minor());
    println!("  ライブラリ実装版: {}.{}", lv.major(), lv.minor());
    println!("  ベンダー        : {}", info.manufacturer_id());
    println!("  説明            : {}", info.library_description());

    // --- ② 各スロット & トークン ---
    let slots = pkcs11.get_slots_with_token()?;
    println!("\n=== トークン入りスロット: {} 個 ===", slots.len());
    for slot in slots {
        let si = pkcs11.get_slot_info(slot)?;
        let ti = pkcs11.get_token_info(slot)?;
        println!("\n[slot id={}] {}", slot.id(), si.slot_description());
        println!("  token ラベル  : {}", ti.label());
        println!("  token 型番    : {}", ti.model());
        println!("  token シリアル: {}", ti.serial_number());

        // --- ③ 対応メカニズム一覧（C_GetMechanismList）+ 各詳細（C_GetMechanismInfo）---
        let mechs = pkcs11.get_mechanism_list(slot)?;
        println!("  対応メカニズム: {} 種", mechs.len());
        for m in mechs {
            // メカニズムごとの詳細（鍵長の上下限など）を取得（= C_GetMechanismInfo）
            match pkcs11.get_mechanism_info(slot, m) {
                Ok(mi) => println!(
                    "    - {m:?}  (key {}..={})",
                    mi.min_key_size(),
                    mi.max_key_size()
                ),
                Err(_) => println!("    - {m:?}"),
            }
        }
    }
    Ok(())
}

/// 現在のセッション状態を表示する（= C_GetSessionInfo）。
pub fn session_info(session: &Session) -> Result<()> {
    let si = session.get_session_info()?;
    println!("=== セッション情報 (C_GetSessionInfo) ===");
    println!("  slot id : {}", si.slot_id().id());
    println!("  状態    : {:?}", si.session_state());
    println!("  RW か   : {}", si.read_write());
    Ok(())
}

/// あるスロットの 1 メカニズムの詳細を表示する（= C_GetMechanismInfo）。
pub fn mechanism_info(pkcs11: &Pkcs11, slot: Slot, mech_name: &str) -> Result<()> {
    for m in pkcs11.get_mechanism_list(slot)? {
        if format!("{m:?}").eq_ignore_ascii_case(mech_name) {
            let mi = pkcs11.get_mechanism_info(slot, m)?;
            println!("{m:?}: {mi:?}");
            println!("  鍵長: {}..={}", mi.min_key_size(), mi.max_key_size());
            return Ok(());
        }
    }
    Err(format!("メカニズム '{mech_name}' はこのスロットの一覧に見つかりません").into())
}
