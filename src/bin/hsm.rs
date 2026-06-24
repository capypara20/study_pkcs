//! cryptoki セットプログラムの CLI 本体。
//!
//! 役割ごとに分けたモジュール(`study_pkcs::ops::*`)を、サブコマンドで呼び分ける。
//!
//! ```text
//! cargo run --bin hsm -- info
//! cargo run --bin hsm -- gen-rsa  [bits]  [label]
//! cargo run --bin hsm -- gen-ec   [label]
//! cargo run --bin hsm -- gen-aes  [bytes] [label]
//! cargo run --bin hsm -- sign     <label> <message>
//! cargo run --bin hsm -- verify   <label> <message> <sig-hex>
//! cargo run --bin hsm -- encrypt  <label> <plaintext>
//! cargo run --bin hsm -- decrypt  <label> <ct-hex>
//! ```
//!
//! 設定は環境変数で渡す:
//! - `PKCS11_LIB`  … .so のパス（既定 `lib/libsofthsm2.so`）
//! - `PKCS11_PIN`  … ユーザ PIN（既定 `1234`）
//! - `PKCS11_SLOT` … スロット index（既定 0 = 最初のトークン入りスロット）

use std::env;

use study_pkcs::ops::{crypt, info, keygen, sign};
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

    // 設定（環境変数 → 既定値）
    let lib = env::var("PKCS11_LIB").unwrap_or_else(|_| "lib/libsofthsm2.so".into());
    let pin = env::var("PKCS11_PIN").unwrap_or_else(|_| "1234".into());
    let slot_index: Option<usize> = env::var("PKCS11_SLOT").ok().and_then(|s| s.parse().ok());

    // info はログイン不要なので接続だけで済ませる
    if cmd == "info" {
        let pkcs11 = session::connect(&lib)?;
        return info::show(&pkcs11);
    }
    if cmd == "help" || cmd == "-h" || cmd == "--help" {
        print_help();
        return Ok(());
    }

    // ここから先はログインが要る操作
    let pkcs11 = session::connect(&lib)?;
    let slot = session::pick_slot(&pkcs11, slot_index)?;
    let s = session::login_rw(&pkcs11, slot, &pin)?;

    match cmd {
        "gen-rsa" => {
            let bits: u64 = arg(&args, 1).unwrap_or("2048").parse()?;
            let label = arg(&args, 2).unwrap_or("my-rsa");
            let (pubk, privk) = keygen::rsa(&s, bits, label)?;
            println!("RSA-{bits} 鍵ペア生成 OK  label='{label}'");
            println!("  pub={pubk:?}  priv={privk:?}");
        }
        "gen-ec" => {
            let label = arg(&args, 1).unwrap_or("my-ec");
            let (pubk, privk) = keygen::ec(&s, label)?;
            println!("EC(P-256) 鍵ペア生成 OK  label='{label}'");
            println!("  pub={pubk:?}  priv={privk:?}");
        }
        "gen-aes" => {
            let bytes: u64 = arg(&args, 1).unwrap_or("32").parse()?;
            let label = arg(&args, 2).unwrap_or("my-aes");
            let key = keygen::aes(&s, bytes, label)?;
            println!("AES-{} 鍵生成 OK  label='{label}'  key={key:?}", bytes * 8);
        }
        "sign" => {
            let label = arg(&args, 1).ok_or("usage: sign <label> <message>")?;
            let msg = arg(&args, 2).ok_or("usage: sign <label> <message>")?;
            let sig = sign::sign(&s, label, msg.as_bytes())?;
            println!("署名 OK ({} バイト)", sig.len());
            println!("  sig(hex) = {}", to_hex(&sig));
        }
        "verify" => {
            let label = arg(&args, 1).ok_or("usage: verify <label> <message> <sig-hex>")?;
            let msg = arg(&args, 2).ok_or("usage: verify <label> <message> <sig-hex>")?;
            let sig = from_hex(arg(&args, 3).ok_or("usage: verify <label> <message> <sig-hex>")?)?;
            match sign::verify(&s, label, msg.as_bytes(), &sig) {
                Ok(()) => println!("検証 OK ✔"),
                Err(e) => println!("検証 NG ({e})"),
            }
        }
        "encrypt" => {
            let label = arg(&args, 1).ok_or("usage: encrypt <label> <plaintext>")?;
            let pt = arg(&args, 2).ok_or("usage: encrypt <label> <plaintext>")?;
            let ct = crypt::encrypt(&s, label, pt.as_bytes())?;
            println!("暗号化 OK ({} バイト)", ct.len());
            println!("  ct(hex) = {}", to_hex(&ct));
        }
        "decrypt" => {
            let label = arg(&args, 1).ok_or("usage: decrypt <label> <ct-hex>")?;
            let ct = from_hex(arg(&args, 2).ok_or("usage: decrypt <label> <ct-hex>")?)?;
            let pt = crypt::decrypt(&s, label, &ct)?;
            println!("復号 OK: {}", String::from_utf8_lossy(&pt));
        }
        other => {
            eprintln!("不明なサブコマンド: {other}\n");
            print_help();
        }
    }
    Ok(())
}

/// args[i] を &str で取り出す（無ければ None）。
fn arg(args: &[String], i: usize) -> Option<&str> {
    args.get(i).map(String::as_str)
}

fn print_help() {
    println!(
        "study_pkcs HSM ツール (cryptoki)\n\
         \n\
         USAGE: cargo run --bin hsm -- <command>\n\
         \n\
         取得系:\n  info                         ライブラリ/スロット/トークン/メカニズム情報\n\
         鍵生成:\n  gen-rsa  [bits]  [label]     RSA 鍵ペア生成 (既定 2048, my-rsa)\n\
         \x20 gen-ec   [label]             EC(P-256) 鍵ペア生成 (既定 my-ec)\n\
         \x20 gen-aes  [bytes] [label]     AES 鍵生成 (既定 32B=AES-256, my-aes)\n\
         署名:\n  sign     <label> <msg>       署名 (SHA256+RSA)\n\
         \x20 verify   <label> <msg> <hex>  検証\n\
         暗号:\n  encrypt  <label> <text>      AES-CBC 暗号化\n\
         \x20 decrypt  <label> <hex>        AES-CBC 復号\n\
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
