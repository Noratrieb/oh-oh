use color_eyre::{Result, eyre::Context};
use rand_core::RngCore;

pub use compute::Totp;

use crate::Db;

mod compute {
    use hmac::Mac;

    pub struct Totp {
        pub digits: String,
    }

    struct TotpConfig {
        digits: u32,
    }

    fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
        //  Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)
        let hs = {
            let mut hmac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
            hmac.update(&counter.to_be_bytes());

            hmac.finalize().into_bytes()
        };

        // Step 2: Generate a 4-byte string (Dynamic Truncation)
        let s = {
            let offset = hs[19] & 0b1111;
            let p = &hs[offset as usize..][..4];
            let p = u32::from_be_bytes(p.try_into().unwrap());
            p & !(1 << 31)
        };

        // Step 3: Compute an HOTP value
        let s = s;

        let d = s % 10_u32.pow(digits);
        format!("{d:0>width$}", width = digits as usize)
    }

    impl Totp {
        pub fn time_step(unix_seconds: i64) -> i64 {
            unix_seconds / 30
        }

        pub fn compute(secret: &str, time_step: i64) -> Self {
            let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret)
                .unwrap_or_default(); // nonsense secret will result in the wrong code as intended

            Self::compute_inner(&secret, time_step, TotpConfig { digits: 6 })
        }

        fn compute_inner(secret: &[u8], time_step: i64, config: TotpConfig) -> Self {
            let code = hotp(secret, time_step as u64, config.digits);
            Totp { digits: code }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::TotpConfig;

        #[test]
        fn test_vectors() {
            let secret = b"12345678901234567890";

            let tests = [
                (59, "94287082"),
                (1111111109, "07081804"),
                (1111111111, "14050471"),
            ];

            for test in tests {
                let totp = super::Totp::compute_inner(
                    secret,
                    super::Totp::time_step(test.0),
                    TotpConfig { digits: 8 },
                );
                assert_eq!(totp.digits, test.1);
            }
        }
    }
}

pub fn generate_secret() -> String {
    let mut bytes = [0_u8; 16]; // decided on by vibes lol
    rand_core::OsRng.fill_bytes(&mut bytes);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}

pub async fn insert_totp_device(db: &Db, user_id: i64, secret: String, name: String) -> Result<()> {
    sqlx::query(
        "insert into totp_devices (user_id, secret, created_time, name) VALUES (?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(secret)
    .bind(jiff::Timestamp::now().as_millisecond())
    .bind(name)
    .execute(&db.pool)
    .await
    .wrap_err("inserting totp device")?;

    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct TotpDevice {
    pub id: i64,
    pub created_time: i64,
    pub name: String,
    pub secret: String,
}

pub async fn list_totp_devices(db: &Db, user_id: i64) -> Result<Vec<TotpDevice>> {
    sqlx::query_as::<_, TotpDevice>(
        "select id, created_time, name, secret from totp_devices where user_id = ?",
    )
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .wrap_err("fetching totp devices")
}

pub async fn delete_totp_device(db: &Db, user_id: i64, totp_device_id: i64) -> Result<()> {
    sqlx::query("delete from totp_devices where id = ? and user_id = ?")
        .bind(totp_device_id)
        .bind(user_id)
        .execute(&db.pool)
        .await
        .wrap_err("failed to delete totp device")?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct UsedTotp {
    pub has_used: i64,
}

pub async fn find_used_totp(db: &Db, user_id: i64, time_step: i64) -> Result<UsedTotp> {
    sqlx::query_as::<_, UsedTotp>(
        "select COUNT(time_step) as has_used from used_totp where user_id = ? and time_step = ?",
    )
    .bind(user_id)
    .bind(time_step)
    .fetch_one(&db.pool)
    .await
    .wrap_err("fetching totp devices")
}

pub async fn insert_used_totp_code(db: &Db, user_id: i64, time_step: i64) -> Result<()> {
    sqlx::query("insert into used_totp (user_id, time_step) values (?, ?)")
        .bind(user_id)
        .bind(time_step)
        .execute(&db.pool)
        .await
        .wrap_err("failed to insert used totp code")?;
    Ok(())
}
