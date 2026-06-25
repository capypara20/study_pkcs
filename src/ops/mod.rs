//! HSM に対する操作を「役割ごと」に分けたモジュール群。
//!
//! | モジュール | 役割 | 対応する C API |
//! |---|---|---|
//! | [`info`]    | 情報取得 | `C_GetInfo` / `C_GetSlotInfo` / `C_GetTokenInfo` / `C_GetMechanismList` / `C_GetMechanismInfo` / `C_GetSessionInfo` |
//! | [`keygen`]  | 鍵生成(RSA/EC/AES) | `C_GenerateKeyPair` / `C_GenerateKey` |
//! | [`sign`]    | 署名・検証(一発) | `C_SignInit`+`C_Sign` / `C_VerifyInit`+`C_Verify` |
//! | [`crypt`]   | 暗号化・復号(一発) | `C_EncryptInit`+`C_Encrypt` / `C_DecryptInit`+`C_Decrypt` |
//! | [`digest`]  | ハッシュ | `C_DigestInit`+`C_Digest` |
//! | [`random`]  | 乱数 | `C_GenerateRandom` / `C_SeedRandom` |
//! | [`objects`] | オブジェクト管理 | `C_FindObjects` / `C_GetAttributeValue` / `C_DestroyObject` / `C_CopyObject` |
//! | [`keywrap`] | 鍵ラップ/導出 | `C_WrapKey` / `C_UnwrapKey` / `C_DeriveKey` |
//! | [`stream`]  | 分割処理 | `C_*Update` / `C_*Final` |
//! | [`admin`]   | トークン/PIN 管理 | `C_InitToken` / `C_InitPIN` / `C_SetPIN` |

pub mod admin;
pub mod crypt;
pub mod digest;
pub mod info;
pub mod keygen;
pub mod keywrap;
pub mod objects;
pub mod random;
pub mod sign;
pub mod stream;
