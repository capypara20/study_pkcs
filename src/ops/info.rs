//! Utility 系 ＝ 取得系コマンド。
//!
//! ログイン不要・Init/Final 不要なので、「ちゃんと HSM に繋がったか」を
//! 最初に確認するのに最適。

use cryptoki::context::Pkcs11;

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

        // --- ③ 対応メカニズム一覧（C_GetMechanismList）---
        let mechs = pkcs11.get_mechanism_list(slot)?;
        println!("  対応メカニズム: {} 種", mechs.len());
        for m in mechs {
            println!("    - {m:?}");
        }
    }
    Ok(())
}
