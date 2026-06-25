//! 乱数（Random）。
//!
//! `C_GenerateRandom` は **ログイン不要・Init/Final 無し**で一番簡単な処理系。
//! HSM のハードウェア乱数生成器(RNG)を使う。

use cryptoki::session::Session;

use crate::Result;

/// HSM の RNG で乱数を生成する（= C_GenerateRandom）。
pub fn generate(session: &Session, len: u32) -> Result<Vec<u8>> {
    let bytes = session.generate_random_vec(len)?;
    Ok(bytes)
}

/// RNG に種(エントロピー)を追加する（= C_SeedRandom）。
pub fn seed(session: &Session, seed: &[u8]) -> Result<()> {
    session.seed_random(seed)?;
    Ok(())
}
