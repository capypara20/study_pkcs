//! cryptoki セットプログラムの CLI 本体。
//!
//! 役割ごとに分けたモジュール(`study_pkcs::ops::*`)を、サブコマンドで呼び分ける。
//! 一覧は `help` を参照。
//!
//! 設定は環境変数で渡す:
//! - `PKCS11_LIB`  … .so のパス（既定 `lib/libsofthsm2.so`）
//! - `PKCS11_PIN`  … ユーザ PIN（既定 `1234`）
//! - `PKCS11_SLOT` … スロット index（既定 0 = 最初のトークン入りスロット）

use std::env;

use study_pkcs::ops::{admin, crypt, digest, info, keygen, keywrap, objects, random, sign, stream};
use study_pkcs::session;
use study_pkcs::Result;

fn main() {
    if let Err(e) = run() {
        eprintln!("エラー: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let lib = env::var("PKCS11_LIB").unwrap_or_else(|_| "lib/libsofthsm2.so".into());
    let pin = env::var("PKCS11_PIN").unwrap_or_else(|_| "1234".into());
    let slot_index: Option<usize> = env::var("PKCS11_SLOT").ok().and_then(|s| s.parse().ok());

    // --- ログイン不要なコマンド（接続だけ） ---
    match cmd {
        "help" | "-h" | "--help" => {
            print_help();
            return Ok(());
        }
        "info" => {
            let pkcs11 = session::connect(&lib)?;
            return info::show(&pkcs11);
        }
        "mech-info" => {
            let name = arg(&args, 1).ok_or("usage: mech-info <MECHANISM>")?;
            let pkcs11 = session::connect(&lib)?;
            let slot = session::pick_slot(&pkcs11, slot_index)?;
            return info::mechanism_info(&pkcs11, slot, name);
        }
        "init-token" => {
            // 破壊的: トークンを初期化（SO-PIN を設定）
            let so_pin = arg(&args, 1).ok_or("usage: init-token <so-pin> <label>")?;
            let label = arg(&args, 2).ok_or("usage: init-token <so-pin> <label>")?;
            let pkcs11 = session::connect(&lib)?;
            let slot = session::pick_slot(&pkcs11, slot_index)?;
            admin::init_token(&pkcs11, slot, so_pin, label)?;
            println!("init-token OK  label='{label}' (⚠️ 中身は消去された)");
            return Ok(());
        }
        _ => {}
    }

    // --- ここから先はログインが要る操作 ---
    let pkcs11 = session::connect(&lib)?;
    let slot = session::pick_slot(&pkcs11, slot_index)?;
    let s = session::login_rw(&pkcs11, slot, &pin)?;

    match cmd {
        // ===== 鍵生成 =====
        "gen-rsa" => {
            let bits: u64 = arg(&args, 1).unwrap_or("2048").parse()?;
            let label = arg(&args, 2).unwrap_or("my-rsa");
            let (pubk, privk) = keygen::rsa(&s, bits, label)?;
            println!("RSA-{bits} 鍵ペア生成 OK  label='{label}'  pub={pubk:?} priv={privk:?}");
        }
        "gen-ec" => {
            let curve = arg(&args, 1).unwrap_or("p256");
            let label = arg(&args, 2).unwrap_or("my-ec");
            let (pubk, privk) = keygen::ec(&s, curve, label)?;
            println!("EC({curve}) 鍵ペア生成 OK  label='{label}'  pub={pubk:?} priv={privk:?}");
        }
        "gen-ed25519" => {
            let label = arg(&args, 1).unwrap_or("my-ed");
            let (pubk, privk) = keygen::ed25519(&s, label)?;
            println!("Ed25519 鍵ペア生成 OK  label='{label}'  pub={pubk:?} priv={privk:?}");
        }
        "gen-x25519" => {
            let label = arg(&args, 1).unwrap_or("my-x");
            let (pubk, privk) = keygen::x25519(&s, label)?;
            println!("X25519 鍵ペア生成 OK  label='{label}'  pub={pubk:?} priv={privk:?}");
        }
        "gen-aes" => {
            let bytes: u64 = arg(&args, 1).unwrap_or("32").parse()?;
            let label = arg(&args, 2).unwrap_or("my-aes");
            let key = keygen::aes(&s, bytes, label)?;
            println!("AES-{} 鍵生成 OK  label='{label}'  key={key:?}", bytes * 8);
        }
        "gen-hmac" => {
            let bytes: u64 = arg(&args, 1).unwrap_or("32").parse()?;
            let label = arg(&args, 2).unwrap_or("my-hmac");
            let key = keygen::generic_secret(&s, bytes, label)?;
            println!("Generic-Secret({} バイト) 生成 OK  label='{label}'  key={key:?}", bytes);
        }

        // ===== 署名・検証（一発） =====
        "sign" => {
            let (label, msg) = two(&args, "sign <label> <message>")?;
            let sig = sign::sign(&s, label, msg.as_bytes())?;
            println!("署名 OK ({} バイト)\n  sig(hex) = {}", sig.len(), to_hex(&sig));
        }
        "verify" => {
            let label = arg(&args, 1).ok_or("usage: verify <label> <message> <sig-hex>")?;
            let msg = arg(&args, 2).ok_or("usage: verify <label> <message> <sig-hex>")?;
            let sig = from_hex(arg(&args, 3).ok_or("usage: verify <label> <message> <sig-hex>")?)?;
            report_verify(sign::verify(&s, label, msg.as_bytes(), &sig));
        }

        // ===== 暗号化・復号（一発） =====
        "encrypt" => {
            let (label, pt) = two(&args, "encrypt <label> <plaintext>")?;
            let ct = crypt::encrypt(&s, label, pt.as_bytes())?;
            println!("暗号化 OK ({} バイト)\n  ct(hex) = {}", ct.len(), to_hex(&ct));
        }
        "decrypt" => {
            let label = arg(&args, 1).ok_or("usage: decrypt <label> <ct-hex>")?;
            let ct = from_hex(arg(&args, 2).ok_or("usage: decrypt <label> <ct-hex>")?)?;
            let pt = crypt::decrypt(&s, label, &ct)?;
            println!("復号 OK: {}", String::from_utf8_lossy(&pt));
        }

        // ===== ダイジェスト =====
        "digest" => {
            let data = arg(&args, 1).ok_or("usage: digest <data>")?;
            let h = digest::sha256(&s, data.as_bytes())?;
            println!("SHA-256 = {}", to_hex(&h));
        }

        // ===== 乱数 =====
        "gen-random" => {
            let len: u32 = arg(&args, 1).unwrap_or("16").parse()?;
            let r = random::generate(&s, len)?;
            println!("random({len}) = {}", to_hex(&r));
        }
        "seed-random" => {
            let seed = from_hex(arg(&args, 1).ok_or("usage: seed-random <hex>")?)?;
            random::seed(&s, &seed)?;
            println!("seed-random OK ({} バイト投入)", seed.len());
        }

        // ===== オブジェクト管理 =====
        "list" => objects::list(&s)?,
        "attrs" => {
            let label = arg(&args, 1).ok_or("usage: attrs <label>")?;
            objects::attrs(&s, label)?;
        }
        "destroy" => {
            let label = arg(&args, 1).ok_or("usage: destroy <label>")?;
            let n = objects::destroy(&s, label)?;
            println!("destroy OK ({n} 個削除)");
        }
        "copy" => {
            let (src, new) = two(&args, "copy <src-label> <new-label>")?;
            let h = objects::copy_with_label(&s, src, new)?;
            println!("copy OK  new={h:?} label='{new}'");
        }

        // ===== 鍵ラップ・導出 =====
        "wrap" => {
            let (wk, target) = two(&args, "wrap <wrapping-aes-label> <target-aes-label>")?;
            let w = keywrap::wrap(&s, wk, target)?;
            println!("wrap OK ({} バイト)\n  wrapped(hex) = {}", w.len(), to_hex(&w));
        }
        "unwrap" => {
            let uk = arg(&args, 1).ok_or("usage: unwrap <unwrapping-label> <hex> <new-label>")?;
            let wrapped = from_hex(arg(&args, 2).ok_or("usage: unwrap <unwrapping-label> <hex> <new-label>")?)?;
            let new = arg(&args, 3).ok_or("usage: unwrap <unwrapping-label> <hex> <new-label>")?;
            let h = keywrap::unwrap(&s, uk, &wrapped, new)?;
            println!("unwrap OK  new={h:?} label='{new}'");
        }
        "derive" => {
            let priv_l = arg(&args, 1).ok_or("usage: derive <ec-priv-label> <peer-ec-pub-label> <new-label>")?;
            let peer_l = arg(&args, 2).ok_or("usage: derive <ec-priv-label> <peer-ec-pub-label> <new-label>")?;
            let new = arg(&args, 3).ok_or("usage: derive <ec-priv-label> <peer-ec-pub-label> <new-label>")?;
            let h = keywrap::derive_ecdh(&s, priv_l, peer_l, new)?;
            println!("derive(ECDH) OK  new={h:?} label='{new}'");
        }

        // ===== 分割処理（マルチパート） =====
        "digest-stream" => {
            let data = arg(&args, 1).ok_or("usage: digest-stream <data>")?;
            let h = stream::digest_sha256(&s, data.as_bytes())?;
            println!("SHA-256(stream) = {}", to_hex(&h));
        }
        "sign-stream" => {
            let (label, msg) = two(&args, "sign-stream <label> <message>")?;
            let sig = stream::sign(&s, label, msg.as_bytes())?;
            println!("署名(stream) OK ({} バイト)\n  sig(hex) = {}", sig.len(), to_hex(&sig));
        }
        "verify-stream" => {
            let label = arg(&args, 1).ok_or("usage: verify-stream <label> <message> <sig-hex>")?;
            let msg = arg(&args, 2).ok_or("usage: verify-stream <label> <message> <sig-hex>")?;
            let sig = from_hex(arg(&args, 3).ok_or("usage: verify-stream <label> <message> <sig-hex>")?)?;
            report_verify(stream::verify(&s, label, msg.as_bytes(), &sig));
        }

        // ===== セッション情報・PIN 管理 =====
        "session-info" => info::session_info(&s)?,
        "init-pin" => {
            let new = arg(&args, 1).ok_or("usage: init-pin <new-pin>")?;
            admin::init_pin(&s, new)?;
            println!("init-pin OK");
        }
        "set-pin" => {
            let (old, new) = two(&args, "set-pin <old-pin> <new-pin>")?;
            admin::set_pin(&s, old, new)?;
            println!("set-pin OK");
        }

        other => {
            eprintln!("不明なサブコマンド: {other}\n");
            print_help();
        }
    }
    Ok(())
}

// ---- 小道具 ----

/// args[i] を &str で取り出す。
fn arg(args: &[String], i: usize) -> Option<&str> {
    args.get(i).map(String::as_str)
}

/// args[1], args[2] をまとめて取り出す（足りなければ usage エラー）。
fn two<'a>(args: &'a [String], usage: &str) -> Result<(&'a str, &'a str)> {
    let a = arg(args, 1).ok_or_else(|| format!("usage: {usage}"))?;
    let b = arg(args, 2).ok_or_else(|| format!("usage: {usage}"))?;
    Ok((a, b))
}

/// 検証結果を表示する。
fn report_verify(r: Result<()>) {
    match r {
        Ok(()) => println!("検証 OK"),
        Err(e) => println!("検証 NG ({e})"),
    }
}

fn print_help() {
    println!(
        "study_pkcs HSM ツール (cryptoki)\n\
         USAGE: cargo run --bin hsm -- <command>\n\
         \n\
         [情報取得]\n\
         \x20 info                          ライブラリ/スロット/トークン/メカニズム\n\
         \x20 mech-info <MECHANISM>         指定メカニズムの詳細(鍵長など)\n\
         \x20 session-info                  セッション状態\n\
         [鍵生成]\n\
         \x20 gen-rsa     [bits]  [label]   RSA 鍵ペア (既定 2048, my-rsa)\n\
         \x20 gen-ec      [curve] [label]   EC 鍵ペア (曲線 p256/p384/p521/secp256k1, 既定 p256)\n\
         \x20 gen-ed25519 [label]           Ed25519 鍵ペア (署名用)\n\
         \x20 gen-x25519  [label]           X25519 鍵ペア (鍵共有用)\n\
         \x20 gen-aes     [bytes] [label]   AES 鍵 (既定 32B=AES-256, my-aes)\n\
         \x20 gen-hmac    [bytes] [label]   Generic-Secret 鍵 (HMAC 用, 既定 32B)\n\
         [署名/検証]\n\
         \x20 sign     <label> <msg>        署名 (SHA256+RSA, 一発)\n\
         \x20 verify   <label> <msg> <hex>  検証\n\
         \x20 sign-stream / verify-stream   分割版(Update/Final)\n\
         [暗号/復号]\n\
         \x20 encrypt  <label> <text>       AES-CBC 暗号化\n\
         \x20 decrypt  <label> <hex>        AES-CBC 復号\n\
         [ハッシュ/乱数]\n\
         \x20 digest        <data>          SHA-256 (一発)\n\
         \x20 digest-stream <data>          SHA-256 (分割版)\n\
         \x20 gen-random  [len]             乱数生成\n\
         \x20 seed-random <hex>             RNG に種を投入\n\
         [オブジェクト管理]\n\
         \x20 list                          全オブジェクト一覧\n\
         \x20 attrs   <label>               属性表示\n\
         \x20 destroy <label>               削除\n\
         \x20 copy    <src> <new>           複製(別ラベル)\n\
         [鍵ラップ/導出]\n\
         \x20 wrap    <wrap-aes> <target>   鍵ラップ\n\
         \x20 unwrap  <unwrap-aes> <hex> <new>  アンラップ\n\
         \x20 derive  <ec-priv> <peer-pub> <new>  ECDH 鍵導出\n\
         [PIN/トークン管理]\n\
         \x20 set-pin  <old> <new>          PIN 変更\n\
         \x20 init-pin <new>                ユーザ PIN 設定(SO ログイン下)\n\
         \x20 init-token <so-pin> <label>   ⚠️トークン初期化(全消去)\n\
         \n\
         環境変数: PKCS11_LIB / PKCS11_PIN / PKCS11_SLOT"
    );
}

/// バイト列 → 16進文字列。
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 16進文字列 → バイト列。
fn from_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex 文字列の長さが奇数です".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}
