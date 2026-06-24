//! HSM に対する操作を「役割ごと」に分けたモジュール群。
//!
//! | モジュール | 役割 | 対応する C API |
//! |---|---|---|
//! | [`info`]   | バージョン・スロット・メカニズムの取得 | `C_GetInfo` / `C_GetSlotInfo` / `C_GetTokenInfo` / `C_GetMechanismList` |
//! | [`keygen`] | 鍵生成(RSA/EC/AES) | `C_GenerateKeyPair` / `C_GenerateKey` |
//! | [`sign`]   | 署名・検証 | `C_SignInit`+`C_Sign` / `C_VerifyInit`+`C_Verify` |
//! | [`crypt`]  | 暗号化・復号 | `C_EncryptInit`+`C_Encrypt` / `C_DecryptInit`+`C_Decrypt` |

pub mod crypt;
pub mod info;
pub mod keygen;
pub mod sign;
