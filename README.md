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
| [doc/06.鍵生成の詳解.md](doc/06.鍵生成の詳解.md) | **鍵生成の深掘り**（属性の意味・RSA/EC/Ed25519/X25519/AES/HMAC の作り方・鍵→署名の対応） |
| [doc/07.ユーザ認証と情報取得.md](doc/07.ユーザ認証と情報取得.md) | **User/SO・PIN・RO/RW・セッション状態**と**情報取得系**（各フィールドの意味） |
| [doc/08.用語・略語集.md](doc/08.用語・略語集.md) | **略語・用語の早見表**（HSM/OID/DER/ECDH/RO/RW/CK* 接頭辞 など） |

---

## cryptoki セットプログラム（`hsm`）

### 機能（やりたいこと → ファイル）

| やりたいこと | ファイル | 関数 |
|---|---|---|
| 情報取得（バージョン/スロット/メカニズム/セッション） | `src/ops/info.rs` | `show()` / `mechanism_info()` / `session_info()` |
| 鍵生成 RSA / EC / Ed25519 / X25519 / AES / HMAC | `src/ops/keygen.rs` | `rsa()` / `ec()` / `ed25519()` / `x25519()` / `aes()` / `generic_secret()` |
| 署名 / 検証（一発） | `src/ops/sign.rs` | `sign()` / `verify()` |
| 暗号化 / 復号（一発） | `src/ops/crypt.rs` | `encrypt()` / `decrypt()` |
| ハッシュ | `src/ops/digest.rs` | `sha256()` |
| 乱数 | `src/ops/random.rs` | `generate()` / `seed()` |
| オブジェクト管理 | `src/ops/objects.rs` | `list()` / `attrs()` / `destroy()` / `copy_with_label()` |
| 鍵ラップ / 導出 | `src/ops/keywrap.rs` | `wrap()` / `unwrap()` / `derive_ecdh()` |
| 分割処理（Update/Final） | `src/ops/stream.rs` | `digest_sha256()` / `sign()` / `verify()` |
| トークン / PIN 管理 | `src/ops/admin.rs` | `init_token()` / `init_pin()` / `set_pin()` |
| 接続・ログイン・鍵検索 | `src/session.rs` | `connect()` / `pick_slot()` / `login_rw()` / `find_key()` |

### 使い方

```bash
# 取得系（ログイン不要・最初の疎通確認に最適）
cargo run --bin hsm -- info

# 鍵生成（アルゴリズム別。詳しくは doc/06）
cargo run --bin hsm -- gen-rsa 2048 mykey
cargo run --bin hsm -- gen-ec  p256 myec       # 曲線 p256/p384/p521/secp256k1
cargo run --bin hsm -- gen-ed25519 myed
cargo run --bin hsm -- gen-aes 32 myaes
cargo run --bin hsm -- gen-hmac 32 myhmac

# 署名 → 検証（sign が出す sig-hex を verify に渡す）
cargo run --bin hsm -- sign   mykey "hello hsm"
cargo run --bin hsm -- verify mykey "hello hsm" <sig-hex>

# 暗号化 → 復号
cargo run --bin hsm -- encrypt myaes "secret"
cargo run --bin hsm -- decrypt myaes <ct-hex>

# ハッシュ・乱数
cargo run --bin hsm -- digest "hello"
cargo run --bin hsm -- gen-random 32

# オブジェクト管理
cargo run --bin hsm -- list
cargo run --bin hsm -- attrs   mykey
cargo run --bin hsm -- destroy mykey

# 鍵ラップ / アンラップ（AES 鍵を AES 鍵で）
cargo run --bin hsm -- gen-aes 32 kek          # 鍵暗号化鍵(KEK)
cargo run --bin hsm -- wrap   kek myaes        # → wrapped(hex)
cargo run --bin hsm -- unwrap kek <wrapped-hex> restored

# 全コマンドは help を参照
cargo run --bin hsm -- help
```

> 注意: `wrap` 対象の鍵は `Extractable=true`、ラップ鍵は `Wrap=true` が要る等、
> 属性の前提がある。詳細は各 `src/ops/*.rs` のコメント参照。

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

**`cryptoki` 0.10 がラッパーを提供する関数はほぼ全て実装済み。**
未実装で残るのは「cryptoki がそもそも安全ラッパーを用意していない関数」だけ（＝生 FFI でしか呼べない）。
関数ごとの詳細は [doc/05](doc/05.PKCS11-関数リファレンス.md) を参照。

| カテゴリ | 実装済み | 未実装（cryptoki 0.10 にラッパー無し） |
|---|---|---|
| 初期化/終了 | `C_Initialize` `C_Finalize` `C_GetFunctionList` | `C_GetFunctionStatus` `C_CancelFunction`（旧式） |
| 情報取得 | `C_GetInfo` `C_GetSlotList` `C_GetSlotInfo` `C_GetTokenInfo` `C_GetMechanismList` `C_GetMechanismInfo` `C_GetSessionInfo` `C_WaitForSlotEvent` | — |
| トークン/PIN管理 | `C_InitToken` `C_InitPIN` `C_SetPIN` | `C_CloseAllSessions` |
| セッション | `C_OpenSession` `C_CloseSession` `C_Login` `C_Logout` | `C_Get/SetOperationState` |
| オブジェクト | `C_FindObjects*` `C_CreateObject` `C_CopyObject` `C_DestroyObject` `C_GetAttributeValue` `C_SetAttributeValue` | `C_GetObjectSize` |
| 鍵管理 | `C_GenerateKey` `C_GenerateKeyPair` `C_WrapKey` `C_UnwrapKey` `C_DeriveKey` | — |
| 署名/検証 | `C_Sign(Init)` `C_Verify(Init)` `C_Sign/VerifyUpdate` `C_Sign/VerifyFinal` | `C_SignRecover*` `C_VerifyRecover*` |
| 暗号/復号 | `C_Encrypt(Init)` `C_Decrypt(Init)` `C_*Update` `C_*Final` | — |
| ダイジェスト | `C_Digest(Init)` `C_DigestUpdate` `C_DigestFinal` `C_DigestKey` | — |
| 乱数 | `C_GenerateRandom` `C_SeedRandom` | — |
| 複合操作 | — | `C_DigestEncryptUpdate` 他 4 種（旧式・性能最適化用） |

> 未実装の `*Recover` / `*OperationState` / 複合操作 / `GetFunctionStatus` / `CancelFunction` / `GetObjectSize` /
> `CloseAllSessions` は、cryptoki 0.10 に安全ラッパーが無いもの。必要なら `src/main.rs` 側の生 FFI 方式で叩く。

---

## ビルド

```bash
cargo build      # 両バイナリ
cargo check      # 型チェックのみ
```

Rust edition **2024**。依存: `cryptoki`（高レベル版）, `libloading` + `object`（生 FFI 版）。
