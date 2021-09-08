use std::error::Error;
use std::io::Cursor;
use std::io::Write;

use crate::otsconfig::OtsConfig;

use crate::plain_buffer::PlainBuffer;
use crate::plain_buffer::Row;
use crate::proto::table_store::UpdateRowRequest;
use crate::utils;
use protobuf::Message;
use reqwest::header::HeaderMap;
use reqwest::Client;
use reqwest::Method;
use reqwest::RequestBuilder;
use reqwest::Response;

use super::proto::table_store::Condition;
use super::proto::table_store::Direction;
use super::proto::table_store::GetRangeRequest;
use super::proto::table_store::GetRangeResponse;
use super::proto::table_store::GetRowRequest;
use super::proto::table_store::GetRowResponse;
use super::proto::table_store::ListTableRequest;
use super::proto::table_store::ListTableResponse;
use super::proto::table_store::PutRowRequest;
use super::proto::table_store::PutRowResponse;
use super::proto::table_store::ReturnContent;
use super::proto::table_store::ReturnType;
use super::proto::table_store::RowExistenceExpectation;

pub struct OtsClient {
    client: Client,
    config: OtsConfig,
}

#[derive(Debug)]
pub struct RangeResult(pub PlainBuffer, pub Vec<u8>);

impl OtsClient {
    pub fn new(config: OtsConfig) -> Self {
        OtsClient {
            client: Client::new(),
            config: config,
        }
    }

    pub async fn list_table(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let listrequest = ListTableRequest::new();
        let mut content = Vec::new();
        listrequest.write_to_vec(&mut content).unwrap();

        let resp = self.request("/ListTable", content).await?;
        if !resp.status().is_success() {
            eprintln!("{:#?}", &resp);
            let msg = format!("Status:{} \n Body:{}\n", resp.status(), resp.text().await?);
            return Err(msg.into());
        }

        let bytes = resp.bytes().await?;
        let list_results = ListTableResponse::parse_from_carllerche_bytes(&bytes)?;

        let table_names = list_results.get_table_names();

        Ok(table_names.to_vec())
    }

    pub async fn put_row(&self, tn: &str, r: Row) -> Result<Row, Box<dyn std::error::Error>> {
        let res = OtsClient::get_plain_buffer(r);

        let mut put = PutRowRequest::new();
        put.set_row(res);
        put.set_table_name(tn.to_string());

        let mut condi = Condition::new();
        condi.set_row_existence(RowExistenceExpectation::IGNORE);
        put.set_condition(condi);

        let mut return_conent = ReturnContent::new();
        return_conent.set_return_type(ReturnType::RT_PK);
        put.set_return_content(return_conent);

        let mut content = Vec::new();
        put.write_to_vec(&mut content).unwrap();

        let resp = self.request("/PutRow", content).await?;
        if !resp.status().is_success() {
            eprintln!("{:#?}", &resp);
            let msg = format!("Status:{} \n Body:{}\n", resp.status(), resp.text().await?);
            return Err(msg.into());
        }

        let mut put_resp = PutRowResponse::parse_from_carllerche_bytes(&resp.bytes().await?)?;
        let mut read = Cursor::new(put_resp.take_row());

        Ok(PlainBuffer::load(&mut read)?
            .rows
            .into_iter()
            .nth(0)
            .unwrap())
    }

    pub async fn update_row(&self, tn: &str, r: Row) -> Result<(), Box<dyn std::error::Error>> {
        let res = OtsClient::get_plain_buffer(r);

        let mut update = UpdateRowRequest::new();
        update.set_row_change(res);
        update.set_table_name(tn.to_string());

        let mut condi = Condition::new();
        condi.set_row_existence(RowExistenceExpectation::EXPECT_EXIST);
        update.set_condition(condi);

        let mut content = Vec::new();
        update.write_to_vec(&mut content).unwrap();

        let resp = self.request("/UpdateRow", content).await?;

        if !resp.status().is_success() {
            eprintln!("{:#?}", &resp);
            let msg = format!("Status:{} \n Body:{}\n", resp.status(), resp.text().await?);
            return Err(msg.into());
        }

        Ok(())
    }

    pub async fn range_get(
        &self,
        tn: &str,
        start: Row,
        end: Row,
        limit: i32,
    ) -> Result<RangeResult, Box<dyn std::error::Error>> {
        self.range_get2(tn, OtsClient::get_plain_buffer(start), end, limit)
            .await
    }

    pub async fn range_get2(
        &self,
        tn: &str,
        start: Vec<u8>,
        end: Row,
        limit: i32,
    ) -> Result<RangeResult, Box<dyn std::error::Error>> {
        let mut range_req = GetRangeRequest::new();
        range_req.set_table_name(tn.to_string());
        range_req.set_direction(Direction::BACKWARD);
        range_req.set_limit(limit);
        range_req.set_max_versions(1);
        range_req.set_inclusive_start_primary_key(start);
        range_req.set_exclusive_end_primary_key(OtsClient::get_plain_buffer(end));

        let mut content = Vec::new();
        range_req.write_to_vec(&mut content)?;

        let resp = self.request("/GetRange", content).await?;
        if !resp.status().is_success() {
            eprintln!("{:#?}", &resp);
            let msg = format!("Status:{} \n Body:{}\n", resp.status(), resp.text().await?);
            return Err(msg.into());
        }

        let mut range_resp = GetRangeResponse::parse_from_carllerche_bytes(&resp.bytes().await?)?;
        let mut read = Cursor::new(range_resp.take_rows());

        Ok(RangeResult(
            PlainBuffer::load(&mut read)?,
            range_resp.take_next_start_primary_key(),
        ))
    }

    pub async fn single_get(&self, tn: &str, get: Row) -> Result<Option<Row>, Box<dyn Error>> {
        let mut get_req = GetRowRequest::new();
        get_req.set_table_name(tn.to_string());
        get_req.set_max_versions(1);
        get_req.set_primary_key(OtsClient::get_plain_buffer(get));

        let content = get_req.write_to_bytes()?;
        let resp = OtsClient::check_response(self.request("/GetRow", content).await?).await?;
        let mut get_resp = GetRowResponse::parse_from_carllerche_bytes(&resp.bytes().await?)?;
        let mut read = Cursor::new(get_resp.take_row());

        Ok(PlainBuffer::load(&mut read)?.rows.into_iter().nth(0))
    }

    async fn request(&self, uri: &str, content: Vec<u8>) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.config.endpoint, uri);

        let mut req: RequestBuilder = self.client.request(Method::POST, &url);
        let headers = self.get_auth_headers(uri, &content);

        req = req.body(content);

        req.headers(headers).send().await
    }

    fn get_plain_buffer(row: Row) -> Vec<u8> {
        let mut write: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut pb = PlainBuffer::new();
        pb.add_row(row);
        pb.save(&mut write);
        write.flush().unwrap();
        let res = write.into_inner();
        res
    }

    fn get_auth_headers(&self, uri: &str, content: &Vec<u8>) -> HeaderMap {
        let mut headers: HeaderMap = HeaderMap::new();

        headers.insert(
            "x-ots-accesskeyid",
            self.config.access_key_id.parse().unwrap(),
        );
        headers.insert("x-ots-apiversion", "2015-12-31".parse().unwrap());

        let content_md5 = utils::content_md5(&content);
        headers.insert("x-ots-contentmd5", content_md5.parse().unwrap());

        let now_utc = utils::get_now_utc();
        headers.insert("x-ots-date", now_utc.parse().unwrap());
        headers.insert("x-ots-instancename", self.config.instance.parse().unwrap());

        // StringToSign = CanonicalURI + '\n' + HTTPRequestMethod + '\n' + CanonicalQueryString + '\n' + CanonicalHeaders + '\n'
        // TODO CanonicalQueryString 为空
        let sign_str = format!(
            "{}\n{}\n{}\n{}",
            uri,
            "POST",
            "",
            self.get_canoical_header_string(&headers)
        );
        let authorization_str = utils::content_sha1(&self.config.access_key_secret, &sign_str);

        headers.insert("x-ots-signature", authorization_str.parse().unwrap());

        headers
    }

    fn get_canoical_header_string(&self, headermap: &HeaderMap) -> String {
        let mut its = headermap
            .keys()
            .into_iter()
            .map(|f| format!("{}", f))
            .collect::<Vec<_>>();
        its.sort();

        let mut res = String::new();
        for key in its {
            res = res
                + &format!(
                    "{}:{}\n",
                    key,
                    headermap.get(&key).unwrap().to_str().unwrap()
                );
        }

        return res;
    }

    async fn check_response(resp: Response) -> Result<Response, Box<dyn Error>> {
        if !resp.status().is_success() {
            eprintln!("{:#?}", &resp);
            let msg = format!("Status:{} \n Body:{}\n", resp.status(), resp.text().await?);
            return Err(msg.into());
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use crate::plain_buffer::Cell;
    use crate::plain_buffer::CellValue;

    use super::*;

    #[rocket::async_test]
    async fn test_otsclient_list_table() {
        let otsclient = OtsClient::new(OtsConfig::test_config());

        let tables = otsclient.list_table().await.unwrap();
        assert!(tables.len() > 0);
    }

    #[rocket::async_test]
    #[ignore = "avoid add too many row"]
    async fn test_otsclient_put_row() {
        let otsclient = OtsClient::new(OtsConfig::test_config());

        let r = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_auto_incr()),
            ],
            vec![
                Cell::create("auth_id", CellValue::create_str("000abc")),
                Cell::create("auth_name", CellValue::create_str("shaoxp用户")),
                Cell::create("auth_gender", CellValue::create_str("1")),
                Cell::create("auth_avartar", CellValue::create_str("000abc")),
                Cell::create(
                    "comment",
                    CellValue::create_str(
                        "因为sqlx对多数据源支持的限制，导致我们现在在用同一个库去管理用户信息．
                        https://github.com/launchbadge/sqlx/issues/916#event-4467087396",
                    ),
                ),
                Cell::create("num_like", CellValue::create_u64(1)),
                Cell::create("u64_test", CellValue::create_u64(12)),
                // Cell::create("bool_test", CellValue::create_bool(false)), it seems does not support boolean!
                Cell::create(
                    "time_creation",
                    CellValue::create_str("2021-08-11:00:22:00z"),
                ),
            ],
        );
        let res = otsclient.put_row("bqs_test", r).await;
        assert!(res.is_ok());

        assert_eq!(res.unwrap().pks.len(), 2);
    }

    #[rocket::async_test]
    async fn test_otsclient_update_row() {
        let otsclient = OtsClient::new(OtsConfig::test_config());

        let r = Row::create_from(
            vec![Cell::create("bq_id", CellValue::create_str("001")),
            Cell::create("comment_id", CellValue::create_u64(1628673673939000))],
            vec![
                Cell::create("auth_name", CellValue::create_str("shaoxp用户update2")),
                Cell::create(
                    "comment",
                    CellValue::create_str(
                        "update2,因为sqlx对多数据源支持的限制，导致我们现在在用同一个库去管理用户信息．
                        https://github.com/launchbadge/sqlx/issues/916#event-4467087396",
                    ),
                ),
                Cell::create("num_like", CellValue::create_u64(3)),                
            ],
        );
        let res = otsclient.update_row("bqs_test", r).await;
        assert!(res.is_ok());
    }

    #[rocket::async_test]
    async fn test_otsclient_range_get() {
        let otsclient = OtsClient::new(OtsConfig::test_config());

        let start = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_u64(2628673674939000 )),
            ],
            vec![],
        );

        let end = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_u64(1628673673939000)),
            ],
            vec![],
        );

        let res = otsclient
            .range_get("bqs_test", start, end, 2)
            .await
            .unwrap();

        assert_eq!(res.0.rows.len(), 2);
        assert!(!res.1.is_empty());

        let end2 = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_u64(1628673673939000)),
            ],
            vec![],
        );
        let res = otsclient
            .range_get2("bqs_test", res.1, end2, 100)
            .await
            .unwrap();
        assert!(res.0.rows.len() > 0);
        assert!(res.1.is_empty());
    }

    #[rocket::async_test]
    async fn test_otsclient_range_get_inf_min_max() {
        let otsclient = OtsClient::new(OtsConfig::test_config());

        let start = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_max()),
            ],
            vec![],
        );

        let end = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_min()),
            ],
            vec![],
        );

        let res = otsclient
            .range_get("bqs_test", start, end, 100)
            .await
            .unwrap();
        assert!(res.0.rows.len() > 10);
        assert!(res.1.is_empty());
    }

    #[rocket::async_test]
    async fn test_otsclient_range_get_empty() {
        let otsclient = OtsClient::new(OtsConfig::test_config());

        let start = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_u64(1528673673939000)),
            ],
            vec![],
        );

        let end = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_min()), 
            ],
            vec![],
        );

        let res = otsclient
            .range_get("bqs_test", start, end, 100)
            .await
            .unwrap();
        assert_eq!(res.0.rows.len(), 0);
        assert!(res.1.is_empty());
    }

    #[rocket::async_test]
    async fn test_otsclient_single_get() {
        let otsclient = OtsClient::new(OtsConfig::test_config());

        let r = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_u64(1628673673939000)),
            ],
            vec![],
        );
        let res = otsclient.single_get("bqs_test", r).await;
        assert!(res.is_ok());

        assert!(res.unwrap().unwrap().attributes.len() > 0);
    }

    #[rocket::async_test]
    async fn test_otsclient_single_get_notexits() {
        let otsclient = OtsClient::new(OtsConfig::test_config());

        let r = Row::create_from(
            vec![
                Cell::create("bq_id", CellValue::create_str("001")),
                Cell::create("comment_id", CellValue::create_u64(73673939000)), // not exits
            ],
            vec![],
        );
        let res = otsclient.single_get("bqs_test", r).await;
        assert!(res.is_ok());

        assert!(res.unwrap().is_none());
    }
}
