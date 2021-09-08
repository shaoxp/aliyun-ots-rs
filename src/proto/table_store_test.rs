
#[cfg(test)]
mod tests {
    use protobuf::Message;

    use crate::proto::table_store::{ListTableRequest, UpdateTableRequest};

    #[test]
    fn test_table_store(){
        let mut update = UpdateTableRequest::new();
        update.set_table_name(String::from("abc"));
        let bytes = &update.write_to_bytes().unwrap()[..];
        println!("{:?}",bytes);

        let get = UpdateTableRequest::parse_from_bytes(bytes).unwrap();
        assert_eq!(get.get_table_name(),"abc");

        let listtable = ListTableRequest::new();

        println!("{:?}",listtable.write_to_bytes());

        let _get = ListTableRequest::parse_from_bytes(&listtable.write_to_bytes().unwrap()[..]).unwrap();
    }
}
