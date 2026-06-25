//! オブジェクト管理（検索・属性読み出し・削除・複製）。
//!
//! 鍵やデータを「一覧表示・中身確認・掃除」できる、運用で一番使うカテゴリ。

use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::Session;

use crate::Result;

/// セッションから見える全オブジェクトを一覧表示する。
///
/// 空テンプレートで [`Session::find_objects`] すると全件ヒットし(= C_FindObjects)、
/// 各ハンドルに [`Session::get_attributes`] で属性を問い合わせる(= C_GetAttributeValue)。
pub fn list(session: &Session) -> Result<()> {
    let handles = session.find_objects(&[])?;
    println!("オブジェクト数: {}", handles.len());
    for h in handles {
        let attrs = session.get_attributes(
            h,
            &[AttributeType::Class, AttributeType::Label, AttributeType::KeyType],
        )?;
        let mut class = String::from("?");
        let mut label = String::from("(no label)");
        let mut key_type = String::new();
        for a in attrs {
            match a {
                Attribute::Class(c) => class = format!("{c:?}"),
                Attribute::Label(v) => label = String::from_utf8_lossy(&v).into_owned(),
                Attribute::KeyType(k) => key_type = format!(" type={k:?}"),
                _ => {}
            }
        }
        println!("  {h:?}  class={class}{key_type}  label='{label}'");
    }
    Ok(())
}

/// 指定ラベルのオブジェクトの主な属性を表示する（= C_GetAttributeValue）。
pub fn attrs(session: &Session, label: &str) -> Result<()> {
    let handles = session.find_objects(&[Attribute::Label(label.as_bytes().to_vec())])?;
    if handles.is_empty() {
        return Err(format!("ラベル '{label}' のオブジェクトが見つかりません").into());
    }
    for h in handles {
        let wanted = [
            AttributeType::Class,
            AttributeType::KeyType,
            AttributeType::Label,
            AttributeType::Token,
            AttributeType::Private,
            AttributeType::Sign,
            AttributeType::Verify,
            AttributeType::Encrypt,
            AttributeType::Decrypt,
            AttributeType::Sensitive,
            AttributeType::Extractable,
            AttributeType::ModulusBits,
        ];
        println!("[{h:?}]");
        for a in session.get_attributes(h, &wanted)? {
            println!("    {a:?}");
        }
    }
    Ok(())
}

/// 指定ラベルに一致するオブジェクトを全て削除する（= C_DestroyObject）。
///
/// 削除した個数を返す。
pub fn destroy(session: &Session, label: &str) -> Result<usize> {
    let handles = session.find_objects(&[Attribute::Label(label.as_bytes().to_vec())])?;
    let mut n = 0;
    for h in handles {
        session.destroy_object(h)?;
        n += 1;
    }
    Ok(n)
}

/// オブジェクトを属性を上書きして複製する（= C_CopyObject）。
///
/// 例: 既存鍵に新しいラベルを付けたコピーを作る。
pub fn copy_with_label(
    session: &Session,
    src_label: &str,
    new_label: &str,
) -> Result<ObjectHandle> {
    let handles = session.find_objects(&[Attribute::Label(src_label.as_bytes().to_vec())])?;
    let src = handles
        .into_iter()
        .next()
        .ok_or_else(|| format!("ラベル '{src_label}' が見つかりません"))?;
    let new = session.copy_object(src, &[Attribute::Label(new_label.as_bytes().to_vec())])?;
    Ok(new)
}
