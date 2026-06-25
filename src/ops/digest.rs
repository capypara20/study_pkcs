//! ダイジェスト（Digest = ハッシュ）。
//!
//! 鍵を使わないので、署名の前段としてだけでなく単体のハッシュ計算にも使える。

use cryptoki::mechanism::Mechanism;
use cryptoki::session::Session;

use crate::Result;

/// データを SHA-256 でハッシュする（= C_DigestInit + C_Digest）。
pub fn sha256(session: &Session, data: &[u8]) -> Result<Vec<u8>> {
    let hash = session.digest(&Mechanism::Sha256, data)?;
    Ok(hash)
}
