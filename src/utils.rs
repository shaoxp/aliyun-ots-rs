use chrono::{DateTime, SecondsFormat, Utc};

pub fn default_or_other<T: Default + PartialEq + Clone>(src: T, other: T) -> T {
    if T::default() == other {
        src
    } else {
        other
    }
}


pub fn text_md5(text: &str) -> String {
    let digest = md5::compute(text.as_bytes());
    base64::encode(digest.0)
}


pub fn content_md5(bytes: &Vec<u8>) -> String {
    let digest = md5::compute(bytes);
    base64::encode(digest.0)
}


pub fn content_sha1(key:&str, text: &str) -> String {
    use hmacsha1::hmac_sha1;

    let digest = hmac_sha1(key.as_bytes(),text.as_bytes());

    base64::encode(&digest)
}

pub fn get_now_gmt() -> String {

    let now: DateTime<Utc> = Utc::now();
    let format_time=now.to_rfc2822().to_string().replace("+0000","GMT");
    return format_time;
}

pub fn get_now_utc()->String{
    let now: DateTime<Utc> = Utc::now();
    let format_time=now.to_rfc3339_opts(SecondsFormat::Millis, true);
    return format_time;
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_xputils_md5() {
        let res = text_md5("");
        assert_eq!(res,"1B2M2Y8AsgTpgAmY7PhCfg==");

        let res= content_md5(&vec![]);
        assert_eq!(res,"1B2M2Y8AsgTpgAmY7PhCfg==");
    }
}