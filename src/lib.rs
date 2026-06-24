//! study_pkcs ライブラリ部
//!
//! `cryptoki` クレートを使って HSM(SoftHSM2 等) を操作するための機能を
//! 「役割ごと」にモジュール分割している。
//!
//! - [`session`] … 接続・スロット選択・ログイン（会話の骨格）
//! - [`ops::info`]   … Utility 系（バージョン・スロット・メカニズム取得）
//! - [`ops::keygen`] … 鍵生成（RSA / EC / AES）
//! - [`ops::sign`]   … 署名・検証
//! - [`ops::crypt`]  … 暗号化・復号
//!
//! CLI 本体は `src/bin/hsm.rs`。

pub mod ops;
pub mod session;

/// このクレート共通の結果型。
///
/// cryptoki 由来のエラー(`cryptoki::error::Error`)も、自前の文字列エラーも
/// `?` 一発でまとめられるよう、トレイトオブジェクトにしている。
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
