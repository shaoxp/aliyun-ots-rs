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
            endpoint: String::from("https://jijixx-te.cn-beijing.ots.aliyuncs.com"),
            access_key_id: String::from("LTAI5tHoQSFAFd3W6AaEyCU7"),
            access_key_secret: String::from("8Gg9JtRafJGR6bqw0XeLLOwyyeAhSc"),
            instance: String::from("jijixx-te"),
        }
    }
}
