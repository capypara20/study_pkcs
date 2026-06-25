# study_pkcs

PKCS#11 と HSM を Rust で学ぶプロジェクト。**2 本立て**で構成している。

| バイナリ | 実体 | 狙い |
|---|---|---|
| `study_pkcs`（既定） | `src/main.rs` | **生 FFI** で C API(`C_Initialize` 等)を手で叩いて仕組みを理解する |
| `hsm` | `src/bin/hsm.rs` ＋ `src/ops/` | **`cryptoki` クレート**で実用的に鍵生成・署名・暗号化を行うセットプログラム |

```bash
cargo run                       # 生 FFI 版（学習用）
cargo run --bin hsm -- help     # cryptoki セットプログラム
```

---

## ドキュメント

| ファイル | 内容 |
|---|---|
| [doc/01.PKCS11-HSM入門.html](doc/01.PKCS11-HSM入門.html) | 基礎概念（Slot/Token/Session/Object/Attribute/Mechanism） |
| [doc/02.PKCS11-操作フロー詳解.html](doc/02.PKCS11-操作フロー詳解.html) | 乱数・署名・鍵生成の 3 段ロケット |
| [doc/03.PKCS11-Rust生FFI実装.html](doc/03.PKCS11-Rust生FFI実装.html) | 生 FFI 実装・型マッピング |
| [doc/04.cryptoki-セットプログラム解説.md](doc/04.cryptoki-セットプログラム解説.md) | cryptoki 版の設計・C API 対応・使い方 |
| [doc/05.PKCS11-関数リファレンス.md](doc/05.PKCS11-関数リファレンス.md) | **全 ~68 関数の早見表**（公式仕様の補完・実装状況つき） |

---

## cryptoki セットプログラム（`hsm`）

### 機能（やりたいこと → ファイル）

| やりたいこと | ファイル | 関数 |
|---|---|---|
| 取得系（バージョン/スロット/メカニズム） | `src/ops/info.rs` | `show()` |
| 鍵生成 RSA / EC / AES | `src/ops/keygen.rs` | `rsa()` / `ec()` / `aes()` |
| 署名 / 検証 | `src/ops/sign.rs` | `sign()` / `verify()` |
| 暗号化 / 復号 | `src/ops/crypt.rs` | `encrypt()` / `decrypt()` |
| 接続・ログイン・鍵検索 | `src/session.rs` | `connect()` / `pick_slot()` / `login_rw()` / `find_key()` |

### 使い方

```bash
# 取得系（ログイン不要・最初の疎通確認に最適）
cargo run --bin hsm -- info

# 鍵生成
cargo run --bin hsm -- gen-rsa 2048 mykey
cargo run --bin hsm -- gen-ec  myec
cargo run --bin hsm -- gen-aes 32 myaes

# 署名 → 検証（sign が出す sig-hex を verify に渡す）
cargo run --bin hsm -- sign   mykey "hello hsm"
cargo run --bin hsm -- verify mykey "hello hsm" <sig-hex>

# 暗号化 → 復号
cargo run --bin hsm -- encrypt myaes "secret"
cargo run --bin hsm -- decrypt myaes <ct-hex>
```

### 設定（環境変数）

| 変数 | 既定 | 意味 |
|---|---|---|
| `PKCS11_LIB` | `lib/libsofthsm2.so` | `.so` のパス |
| `PKCS11_PIN` | `1234` | ユーザ PIN |
| `PKCS11_SLOT` | `0` | スロット index |

実機 HSM へ移すときは、基本この 3 つを差し替えるだけ。

### 事前準備（SoftHSM2）

```bash
# トークン初期化（PIN とラベルをここで決める）
softhsm2-util --init-token --slot 0 --label "test" --so-pin 1234 --pin 1234
# 共有ライブラリを lib/ に配置（または PKCS11_LIB で指定）
```

---

## このプログラムの API カバレッジ

⚠️ **「PKCS#11 をほぼ網羅」ではない。** 全 ~68 関数のうち、**日常的に使う中核フロー ~20 個**だけを実装している（下表）。
未実装分の一覧と意味は [doc/05](doc/05.PKCS11-関数リファレンス.md) を参照。

| カテゴリ | 実装済み | 未実装（代表例） |
|---|---|---|
| 初期化/終了 | `C_Initialize` `C_Finalize` `C_GetFunctionList` | `C_GetFunctionStatus` `C_CancelFunction` |
| 情報取得 | `C_GetInfo` `C_GetSlotList` `C_GetSlotInfo` `C_GetTokenInfo` `C_GetMechanismList` | `C_GetMechanismInfo` `C_GetSessionInfo` `C_WaitForSlotEvent` |
| トークン/PIN管理 | — | `C_InitToken` `C_InitPIN` `C_SetPIN` |
| セッション | `C_OpenSession` `C_CloseSession` `C_Login` `C_Logout` | `C_CloseAllSessions` `C_Get/SetOperationState` |
| オブジェクト | `C_FindObjects*` | `C_CreateObject` `C_CopyObject` `C_DestroyObject` `C_Get/SetAttributeValue` `C_GetObjectSize` |
| 鍵管理 | `C_GenerateKey` `C_GenerateKeyPair` | `C_WrapKey` `C_UnwrapKey` `C_DeriveKey` |
| 署名/検証 | `C_Sign` `C_Verify`（一発） | `*Update`/`*Final`（分割） `*Recover` 系 |
| 暗号/復号 | `C_Encrypt` `C_Decrypt`（一発） | `*Update`/`*Final`（分割） |
| ダイジェスト | — | `C_Digest*` |
| 乱数 | — | `C_GenerateRandom` `C_SeedRandom` |
| 複合操作 | — | `C_DigestEncryptUpdate` 他 |

---

## ビルド

```bash
cargo build      # 両バイナリ
cargo check      # 型チェックのみ
```

Rust edition **2024**。依存: `cryptoki`（高レベル版）, `libloading` + `object`（生 FFI 版）。
