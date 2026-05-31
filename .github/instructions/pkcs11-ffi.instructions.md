---
applyTo: "src/**/*.rs"
---

# PKCS#11 Rust 生 FFI — コーディング規約

このプロジェクトは PKCS#11 を Rust 生 FFI で一から実装して学ぶ。
コードを書く前に [doc/03.PKCS11-Rust生FFI実装.html](../../doc/03.PKCS11-Rust生FFI実装.html) を参照すること。

---

## モジュール構成

| ファイル                   | 役割                                    |
| -------------------------- | --------------------------------------- |
| `src/ffi/types.rs`         | `CK_ULONG`, `CK_RV` などの基本型        |
| `src/ffi/constants.rs`     | `CKR_*`, `CKO_*`, `CKM_*` 定数          |
| `src/ffi/function_list.rs` | `CK_FUNCTION_LIST` 構造体               |
| `src/error.rs`             | `CK_RV` → `Result<T, PkcsError>` 変換   |
| `src/loader.rs`            | `libloading` で `.so` を動的ロード      |
| `src/session.rs`           | セッションライフサイクル管理            |
| `src/ops/random.rs`        | `C_GenerateRandom`                      |
| `src/ops/sign.rs`          | `C_SignInit` / `C_Sign` / `C_SignFinal` |
| `src/ops/keygen.rs`        | `C_GenerateKey` / `C_GenerateKeyPair`   |

---

## 必須ルール

### 型定義

- FFI 構造体には必ず `#[repr(C)]` を付ける
- `CK_FUNCTION_LIST` のフィールド順は **仕様書の順序と完全一致**（ズレると未定義動作）
- C 型マッピング: `CK_ULONG` → `c_ulong`、ポインタ → `*const c_void` / `*mut c_void`

### unsafe

- FFI 呼び出しは `unsafe` ブロックに閉じ込める
- `ops/` の公開 API は safe なラッパーとして実装する
- ポインタは必ずヌルチェックしてから参照外し（`is_null()` を使う）

### エラー処理

- PKCS#11 関数の戻り値は `CK_RV`（`c_ulong`）。`0 = CKR_OK`
- `0` 以外は `error.rs` の `PkcsError` に変換して `Err(...)` を返す
- `unwrap()` を FFI 境界で使わない

### ライブラリ読み込み

- SoftHSM2 のパスは `lib/libsofthsm2.so`
- パスはハードコードせず、引数や設定から渡す

---

## 操作フロー（3段ロケット）

詳細は [doc/02.PKCS11-操作フロー詳解.html](../../doc/02.PKCS11-操作フロー詳解.html) を参照。

```
Initialize → OpenSession → Login
    ↓
[操作ごとの Init] → [Sign / Encrypt / ...] → [Final]
    ↓
Logout → CloseSession → Finalize
```

---

## 依存クレート

```toml
libloading = "0.9"   # .so 動的ロード
object     = "0.32"  # ELF からシンボル一覧取得
```
