# study_pkcs — AI Agent Instructions

PKCS#11 を Rust 生 FFI で一から実装して学ぶプロジェクト。
SoftHSM2 の `.so` を動的ロードし、HSM の操作フローをコードで追体験する。

---

## ドキュメント

| ファイル | 内容 |
|---|---|
| [doc/01.PKCS11-HSM入門.html](doc/01.PKCS11-HSM入門.html) | HSM・PKCS#11 の基礎概念 (Slot/Token/Session/Object/Attribute/Mechanism) |
| [doc/02.PKCS11-操作フロー詳解.html](doc/02.PKCS11-操作フロー詳解.html) | 乱数生成・署名・鍵生成の 3段ロケット操作フロー |
| [doc/03.PKCS11-Rust生FFI実装.html](doc/03.PKCS11-Rust生FFI実装.html) | Rust モジュール構成・型マッピング・FFI 落とし穴 |

コードを書く前に必ずドキュメントを参照すること。

---

## ビルド・実行

```bash
# ビルド
cargo build

# 実行（lib/libsofthsm2.so が必要）
cargo run

# チェックのみ
cargo check
```

Rust edition **2024** を使用。

---

## プロジェクト構成（目標）

[doc/03](doc/03.PKCS11-Rust生FFI実装.html) のモジュール設計に従うこと。

```
src/
├── main.rs           # エントリポイント・配線
├── error.rs          # CK_RV → Result 変換
├── loader.rs         # libloading で .so 動的ロード
├── session.rs        # セッションライフサイクル管理
├── ffi/
│   ├── mod.rs
│   ├── types.rs      # CK_ULONG, CK_RV などの基本型
│   ├── constants.rs  # CKR_*, CKO_* 定数
│   └── function_list.rs  # CK_FUNCTION_LIST 構造体
└── ops/
    ├── random.rs     # C_GenerateRandom
    ├── sign.rs       # C_Sign / C_SignInit / C_SignFinal
    └── keygen.rs     # C_GenerateKeyPair / C_GenerateKey
```

---

## 重要な規約

### FFI 型定義
- すべての FFI 構造体に `#[repr(C)]` を付ける（必須）
- `CK_FUNCTION_LIST` のフィールド順は仕様書の順序と **完全に一致** させる（ズレると未定義動作）
- C 型のマッピング: `CK_ULONG` → `c_ulong`、`CK_RV` → `c_ulong`、ポインタ → `*const c_void` / `*mut c_void`

### unsafe の扱い
- FFI 呼び出しは必ず `unsafe` ブロックに閉じ込める
- 公開 API レイヤー（`ops/`）は safe なラッパーとして実装する
- ポインタのヌルチェックを怠らない

### エラー処理
- PKCS#11 関数は `CK_RV`（`c_ulong`）を返す。`0 = CKR_OK`
- `error.rs` で `CK_RV` を `Result<T, PkcsError>` に変換して使う

### ライブラリパス
- SoftHSM2 の共有ライブラリは `lib/libsofthsm2.so` に配置する
- パスはハードコードせず、設定や引数で渡す設計を目指す

---

## 依存クレート

| クレート | 用途 |
|---|---|
| `libloading = "0.9"` | `.so` の動的ロード |
| `object = "0.32"` | ELF バイナリからシンボル一覧を取得 |

---

## 参考リスト

PKCS#11 の全関数一覧は [example_fnList.txt](example_fnList.txt) を参照。
