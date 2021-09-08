#[derive(Debug)]
pub struct OtsConfig {
    pub endpoint: String,
    pub access_key_id: String,
    pub access_key_secret: String,
    pub instance: String,
}

impl OtsConfig {
    pub fn test_config() -> OtsConfig {
        OtsConfig {
            endpoint: String::from(""),
            access_key_id: String::from(""),
            access_key_secret: String::from(""),
            instance: String::from("jijixx-te"),
        }
    }
}
