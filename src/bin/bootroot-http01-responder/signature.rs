//! Provides header parsing and timestamp checks for admin requests.

use std::time::{SystemTime, UNIX_EPOCH};

use poem::Request;

pub(super) fn header_value(req: &Request, key: &str) -> Result<String, String> {
    req.headers()
        .get(key)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .ok_or_else(|| format!("Missing header: {key}"))
}

pub(super) fn within_skew(timestamp: i64, max_skew_secs: u64) -> bool {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => match i64::try_from(value.as_secs()) {
            Ok(secs) => secs,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    (now - timestamp).unsigned_abs() <= max_skew_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_within_skew_rejects_out_of_range() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time must be after UNIX_EPOCH")
            .as_secs();
        let now = i64::try_from(now).expect("System time must fit in i64");

        assert!(within_skew(now, 60));
        assert!(!within_skew(now - 3600, 60));
    }
}
