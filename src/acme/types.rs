use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Order {
    pub status: OrderStatus,
    pub finalize: String,
    pub authorizations: Vec<String>,
    pub certificate: Option<String>,
    #[serde(skip)]
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Authorization {
    pub status: AuthorizationStatus,
    #[serde(rename = "identifier")]
    _identifier: serde_json::Value,
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub r#type: ChallengeType,
    pub url: String,
    pub token: String,
    pub status: ChallengeStatus,
    pub error: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_order_status_deserialization() {
        let cases = vec![
            ("\"pending\"", OrderStatus::Pending),
            ("\"ready\"", OrderStatus::Ready),
            ("\"processing\"", OrderStatus::Processing),
            ("\"valid\"", OrderStatus::Valid),
            ("\"invalid\"", OrderStatus::Invalid),
        ];
        for (json, expected) in cases {
            let status: OrderStatus = serde_json::from_str(json).unwrap();
            assert_eq!(status, expected);
        }
    }

    #[test]
    fn test_challenge_type_deserialization() {
        let json = r#""http-01""#;
        let c_type: ChallengeType = serde_json::from_str(json).unwrap();
        assert_eq!(c_type, ChallengeType::Http01);
        let json = r#""dns-01""#;
        let c_type: ChallengeType = serde_json::from_str(json).unwrap();
        assert_eq!(c_type, ChallengeType::Dns01);
    }
}
