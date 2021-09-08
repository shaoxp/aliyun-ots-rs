use std::convert::TryInto;
use std::io::Error;
use std::io::Read;
use std::io::Write;

use super::crc8;

const TAG_HEADER: u32 = 0x75u32;

// tag type
const TAG_PK: u8 = 0x1;
const TAG_ATTR: u8 = 0x2;
const TAG_CELL: u8 = 0x3;
const TAG_CELL_NAME: u8 = 0x4;
const TAG_CELL_VALUE: u8 = 0x5;
const TAG_CELL_OP: u8 = 0x6;
const TAG_CELL_TIMESTAMP: u8 = 0x7;
const TAG_DELETE_ROW_MARKER: u8 = 0x8;
const TAG_ROW_CHECKSUM: u8 = 0x9;
const TAG_CELL_CHECKSUM: u8 = 0x0A;
// const TAG_EXTENSION: u8 = 0x0B;
// const TAG_SEQ_INFO: u8 = 0x0C;
// const TAG_SEQ_INFO_EPOCH: u8 = 0x0D;
// const TAG_SEQ_INFO_TS: u8 = 0x0E;
// const TAG_SEQ_INFO_ROW_INDEX: u8 = 0x0F;

// cell op type
const DELETE_ALL_VERSION: u8 = 0x1;
const DELETE_ONE_VERSION: u8 = 0x3;
// const INCREMENT: u8 = 0x4;

// variant type
const VT_INTEGER: u8 = 0x0;
const VT_DOUBLE: u8 = 0x1;
const VT_BOOLEAN: u8 = 0x2;
const VT_STRING: u8 = 0x3;

//public final static byte VT_NULL = 0x6;
const VT_BLOB: u8 = 0x7;
const VT_INF_MIN: u8 = 0x9;
const VT_INF_MAX: u8 = 0xa;
const VT_AUTO_INCREMENT: u8 = 0xb;

const LITTLE_ENDIAN_32_SIZE: u32 = 4;
const LITTLE_ENDIAN_64_SIZE: u32 = 8;

#[derive(Debug)]
pub struct PlainBuffer {
    pub rows: Vec<Row>,
}

#[derive(Debug)]
pub struct Row {
    pub pks: Vec<Cell>,
    pub attributes: Vec<Cell>,
    pub is_delete_marker: bool,
}

#[derive(Debug)]
pub struct Cell {
    pub cell_name: String,
    pub cell_value: Option<CellValue>,
    pub cell_op: Option<CellOp>,
    pub cell_ts: Option<u64>,
}

#[derive(Debug)]
pub struct CellValue {
    pub value_type: CellValueType,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub enum CellOp {
    DeleteAllVersion,
    DeleteOneVersion,
}

#[derive(Debug,PartialEq)]
pub enum CellValueType {
    String,
    Int,
    Double,
    Bool,
    Bin,

    AutoIncr,
    InfMin,
    InfMax,
}

impl PlainBuffer {
    pub fn new() -> PlainBuffer {
        PlainBuffer { rows: vec![] }
    }

    pub fn add_row(&mut self, r: Row) {
        self.rows.push(r);
    }

    pub fn save(&self, w: &mut dyn Write) {
        save32(w, &TAG_HEADER);

        for r in &self.rows {
            r.save(w);
        }
    }

    pub fn load(r: &mut dyn Read) -> Result<PlainBuffer, Error> {
        let mut pb = PlainBuffer::new();
        let head = read32(r);
        if head.is_err(){
            // empty result.
            return Ok(pb);
        }

        if head.unwrap() != TAG_HEADER {
            panic!("wrong header!");
        }

       
        loop {
            let row = Row::load(r);
            match row {
                Ok(r) => pb.add_row(r),
                Err(_e) => break,
            }
        }

        Ok(pb)
    }
}

impl Row {
    pub fn new() -> Row {
        Row {
            pks: vec![],
            attributes: vec![],
            is_delete_marker: false,
        }
    }

    pub fn create_from(pks: Vec<Cell>, attr: Vec<Cell>) -> Row {
        Row {
            pks: pks,
            attributes: attr,
            is_delete_marker: false,
        }
    }

    pub fn add_pk(&mut self, c: Cell) {
        self.pks.push(c);
    }

    pub fn add_attr(&mut self, c: Cell) {
        self.attributes.push(c);
    }

    pub fn save(&self, w: &mut dyn Write) {
        if !self.pks.is_empty() {
            save8(w, &TAG_PK);
            for pk in &self.pks {
                pk.save(w);
            }
        }

        if !self.attributes.is_empty() {
            save8(w, &TAG_ATTR);
            for cell in &self.attributes {
                cell.save(w);
            }
        }

        if self.is_delete_marker {
            save8(w, &TAG_DELETE_ROW_MARKER);
        }

        save8(w, &TAG_ROW_CHECKSUM);
        save8(w, &self.get_checksum(0));
    }

    pub fn load(r: &mut dyn Read) -> Result<Row, Error> {
        let mut tag = read8(r)?;
        let mut row = Row::new();

        if tag == TAG_PK {
            loop {
                match Cell::load(r) {
                    Ok(cell) => row.pks.push(cell),
                    Err(last_tag) => {
                        tag = last_tag;
                        break;
                    }
                }
            }
        }

        if tag == TAG_ATTR {
            loop {
                match Cell::load(r) {
                    Ok(cell) => row.attributes.push(cell),
                    Err(last_tag) => {
                        tag = last_tag;
                        break;
                    }
                }
            }
        }

        if tag == TAG_DELETE_ROW_MARKER {
            row.is_delete_marker = true;
            tag = read8(r)?;
        }

        if tag == TAG_ROW_CHECKSUM {
            read8(r)?;
        } else {
            panic!("missing check sum");
        }
        Ok(row)
    }

    fn get_checksum(&self, crc: u8) -> u8 {
        let mut crc = crc;
        for pk in &self.pks {
            let crc_cell = pk.get_checksum(0x0);
            crc = crc8::crc8_byte(crc, crc_cell);
        }

        for attr in &self.attributes {
            let crc_cell = attr.get_checksum(0x0);
            crc = crc8::crc8_byte(crc, crc_cell);
        }

        let del = if self.is_delete_marker { 0x01u8 } else { 0x0u8 };

        crc = crc8::crc8_byte(crc, del);

        return crc;
    }

    pub fn get_pk_cell(&self, cellname:&str)->Option<&Cell>{
        self.pks.iter().find(|c|c.cell_name == cellname)
    }

    pub fn get_attribute_cell(&self, cellname:&str)->Option<&Cell>{
        self.attributes.iter().find(|c|c.cell_name == cellname)
    }
}

impl Cell {
    pub fn new(cellname: &str) -> Cell {
        Cell {
            cell_name: cellname.to_string(),
            cell_value: None,
            cell_op: None,
            cell_ts: None,
        }
    }

    pub fn create(cn: &str, cv: CellValue) -> Cell {
        Cell {
            cell_name: cn.to_string(),
            cell_value: Some(cv),
            cell_op: None,
            cell_ts: None,
        }
    }
    pub fn save(&self, w: &mut dyn Write) {
        save8(w, &TAG_CELL);

        save8(w, &TAG_CELL_NAME);
        save_formated_str(w, self.cell_name.as_str());

        if self.cell_value.is_some() {
            self.cell_value.as_ref().unwrap().save(w);
        }

        if self.cell_op.is_some() {
            save8(w, &TAG_CELL_OP);
            save_cell_op(w, &self.cell_op.as_ref().unwrap());
        }

        if self.cell_ts.is_some() {
            save8(w, &TAG_CELL_TIMESTAMP);
            save64(w, &self.cell_ts.unwrap());
        }

        save8(w, &TAG_CELL_CHECKSUM);
        save8(w, &self.get_checksum(0))
    }

    // here we return the next tag to remove dependency for seek.
    pub fn load(r: &mut dyn Read) -> Result<Cell, u8> {
        let tag = read8(r).unwrap();
        if tag == TAG_CELL {
            let mut tag = read8(r).unwrap();
            if tag != TAG_CELL_NAME {
                panic!("missing cell name!")
            }
            let namesize = read32(r).unwrap();
            let mut namebyte = vec![0u8; namesize as usize];
            read_bytes(r, &mut namebyte[..]).unwrap();
            let mut cell = Cell::new(String::from_utf8(namebyte).unwrap().as_str());

            match CellValue::load(r) {
                Ok(cell_value) => {
                    cell.cell_value = Some(cell_value);
                    tag = read8(r).unwrap();
                }
                Err(last_tag) => {
                    tag = last_tag;
                }
            }

            if tag == TAG_CELL_OP {
                read8(r).unwrap();
                tag = read8(r).unwrap();
            }
            if tag == TAG_CELL_TIMESTAMP {
                cell.cell_ts = Some(read64(r).unwrap());
                tag = read8(r).unwrap();
            }
            if tag == TAG_CELL_CHECKSUM {
                read8(r).unwrap();
            } else {
                println!("wrong tag :{}", tag);
                panic!("missing check sum!")
            }
            Ok(cell)
        } else {
            Err(tag)
        }
    }

    fn get_checksum(&self, crc: u8) -> u8 {
        let mut crc = crc8::crc8_bytes(crc, self.cell_name.as_bytes());

        if self.cell_value.is_some() {
            crc = self.cell_value.as_ref().unwrap().get_checksum(crc)
        }

        if self.cell_ts.is_some() {
            crc = crc8::crc8_int64(crc, self.cell_ts.unwrap());
        }

        if self.cell_op.is_some() {
            crc = crc8::crc8_byte(
                crc,
                match self.cell_op.as_ref().unwrap() {
                    CellOp::DeleteAllVersion => DELETE_ALL_VERSION,
                    CellOp::DeleteOneVersion => DELETE_ONE_VERSION,
                },
            )
        }
        crc
    }

    pub fn as_u64(&self)->Option<u64>{
        match &self.cell_value {
            Some(c)=>c.as_u64(),
            None=>None    
        }
    }

    pub fn as_string(&self)->Option<String>{
        match &self.cell_value {
            Some(c)=>c.as_string(),
            None=>None    
        }
    }
}

impl CellValue {
    pub fn new(t: CellValueType, bs: Vec<u8>) -> CellValue {
        CellValue {
            value_type: t,
            value: bs,
        }
    }

    pub fn create_str(s: &str) -> CellValue {
        CellValue {
            value_type: CellValueType::String,
            value: s.as_bytes().to_vec(),
        }
    }

    pub fn create_u64(u: u64) -> CellValue {
        CellValue {
            value_type: CellValueType::Int,
            value: u.to_le_bytes().to_vec(),
        }
    }

    pub fn create_bool(b: bool) -> CellValue {
        if b {
            CellValue {
                value_type: CellValueType::Bool,
                value: vec![0x1b_u8],
            }
        } else {
            CellValue {
                value_type: CellValueType::Bool,
                value: vec![0x0b_u8],
            }
        }
    }

    pub fn create_auto_incr() -> CellValue {
        CellValue {
            value_type: CellValueType::AutoIncr,
            value: vec![],
        }
    }


    pub fn create_min()->CellValue{
        CellValue{
            value_type:CellValueType::InfMin,
            value:vec![],
        }
    }

    pub fn create_max()->CellValue{
        CellValue{
            value_type:CellValueType::InfMax,
            value:vec![],
        }
    }
    
    pub fn create_bin(bin: Vec<u8>) -> CellValue {
        CellValue {
            value_type: CellValueType::Bin,
            value: bin,
        }
    }
    pub fn save(&self, w: &mut dyn Write) {
        save8(w, &TAG_CELL_VALUE);
        match self.value_type {
            CellValueType::AutoIncr => {
                save32(w, &1);
                save8(w, &VT_AUTO_INCREMENT);
            }
            CellValueType::InfMin => {
                save32(w, &1);
                save8(w, &VT_INF_MIN);
            }
            CellValueType::InfMax => {
                save32(w, &1);
                save8(w, &VT_INF_MAX);
            }

            CellValueType::String => {
                save32(w, &((self.value.len() as u32) + LITTLE_ENDIAN_32_SIZE + 1)); // length + type + value
                save8(w, &VT_STRING);
                save32(w, &(self.value.len() as u32));
            }
            CellValueType::Int => {
                save32(w, &(LITTLE_ENDIAN_64_SIZE + 1));
                save8(w, &VT_INTEGER);
            }
            CellValueType::Double => {
                save32(w, &(LITTLE_ENDIAN_64_SIZE + 1));
                save8(w, &VT_DOUBLE);
            }
            CellValueType::Bool => {
                save32(w, &2);
                save8(w, &VT_BOOLEAN);
            }
            CellValueType::Bin => {
                save32(w, &((self.value.len() as u32) + LITTLE_ENDIAN_32_SIZE + 1)); // length + type + value
                save8(w, &VT_BLOB);
                save32(w, &(self.value.len() as u32));
            }
        }

        save_bytes(w, &self.value[..]);
    }

    pub fn load(r: &mut dyn Read) -> Result<CellValue, u8> {
        let tag = read8(r).unwrap();
        if tag == TAG_CELL_VALUE {
            read32(r).unwrap(); // ignored field!
            match read8(r).unwrap() {
                VT_INTEGER => {
                    let mut value = vec![0u8; 8];
                    read_bytes(r, &mut value[..]).unwrap();
                    Ok(CellValue::new(CellValueType::Int, value))
                }
                VT_DOUBLE => {
                    let mut value = vec![0u8; 8];
                    read_bytes(r, &mut value[..]).unwrap();
                    Ok(CellValue::new(CellValueType::Double, value))
                }
                VT_BOOLEAN => {
                    let mut value = vec![0u8; 1];
                    read_bytes(r, &mut value[..]).unwrap();
                    Ok(CellValue::new(CellValueType::Bool, value))
                }

                VT_STRING => {
                    let sz = read32(r).unwrap();
                    let mut value = vec![0u8; sz as usize];
                    read_bytes(r, &mut value[..]).unwrap();
                    Ok(CellValue::new(CellValueType::String, value))
                }

                VT_BLOB => {
                    let sz = read32(r).unwrap();
                    let mut value = vec![0u8; sz as usize];
                    read_bytes(r, &mut value[..]).unwrap();
                    Ok(CellValue::new(CellValueType::Bin, value))
                }
                _ => panic!("not support type!"),
            }
        } else {
            Err(tag)
        }
    }

    pub fn get_checksum(&self, crc: u8) -> u8 {
        let mut crc = crc;
        match self.value_type {
            CellValueType::AutoIncr => {
                crc = crc8::crc8_byte(crc, VT_AUTO_INCREMENT);
            }

            CellValueType::InfMin => {
                crc = crc8::crc8_byte(crc, VT_INF_MIN);
            }

            CellValueType::InfMax => {
                crc = crc8::crc8_byte(crc, VT_INF_MAX);
            }

            CellValueType::String => {
                crc = crc8::crc8_byte(crc, VT_STRING);
                crc = crc8::crc8_int32(crc, self.value.len() as u32);
            }
            CellValueType::Int => {
                crc = crc8::crc8_byte(crc, VT_INTEGER);
            }
            CellValueType::Double => {
                crc = crc8::crc8_byte(crc, VT_INTEGER);
            }
            CellValueType::Bool => {
                crc = crc8::crc8_byte(crc, VT_BOOLEAN);
            }
            CellValueType::Bin => {
                crc = crc8::crc8_byte(crc, VT_BLOB);
                crc = crc8::crc8_int32(crc, self.value.len() as u32);
            }
        }
        crc = crc8::crc8_bytes(crc, &self.value[..]);

        return crc;
    }

    pub fn as_u64(&self) -> Option<u64> {
        if CellValueType::Int == self.value_type {
            let bytes= self.value.clone().try_into().unwrap();
            Some(u64::from_le_bytes(bytes))
        }else{
            None
        }
    }

    pub fn as_string(&self)->Option<String>{
        if CellValueType::String == self.value_type {
            let bytes= self.value.clone().try_into().unwrap();
            Some(String::from_utf8(bytes).unwrap())
        }else{
            None
        }
    }
}

fn save8(w: &mut dyn Write, d: &u8) {
    w.write(&[*d]).unwrap();
}

fn read8(r: &mut dyn Read) -> Result<u8, Error> {
    let mut d = [0u8];
    r.read_exact(&mut d)?;

    Ok(d[0])
}

fn save32(w: &mut dyn Write, d: &u32) {
    let bytes = [
        (d & 0xFF) as u8,
        ((d >> 8) & 0xFF) as u8,
        ((d >> 16) & 0xFF) as u8,
        ((d >> 24) & 0xFF) as u8,
    ];
    w.write(&bytes).unwrap();
}

fn read32(r: &mut dyn Read) -> Result<u32, Error> {
    let mut d = [0u8; 4];
    r.read_exact(&mut d)?;

    Ok(u32::from_le_bytes(d))
}

fn save64(w: &mut dyn Write, d: &u64) {
    let bytes = [
        (d & 0xFF) as u8,
        ((d >> 8) & 0xFF) as u8,
        ((d >> 16) & 0xFF) as u8,
        ((d >> 24) & 0xFF) as u8,
        ((d >> 32) & 0xFF) as u8,
        ((d >> 40) & 0xFF) as u8,
        ((d >> 48) & 0xFF) as u8,
        ((d >> 56) & 0xFF) as u8,
    ];
    w.write(&bytes).unwrap();
}

fn read64(r: &mut dyn Read) -> Result<u64, Error> {
    let mut d = [0u8; 8];
    r.read_exact(&mut d)?;

    Ok(u64::from_le_bytes(d))
}

fn save_bytes(w: &mut dyn Write, d: &[u8]) {
    w.write(d).unwrap();
}

fn read_bytes(r: &mut dyn Read, buf: &mut [u8]) -> Result<(), Error> {
    r.read_exact(buf)?;
    Ok(())
}

fn save_cell_op(w: &mut dyn Write, d: &CellOp) {
    match d {
        CellOp::DeleteAllVersion => save8(w, &DELETE_ALL_VERSION),
        CellOp::DeleteOneVersion => save8(w, &DELETE_ONE_VERSION),
    }
}

fn save_formated_str(w: &mut dyn Write, d: &str) {
    // save8(w, &VT_STRING);
    let db = d.as_bytes();
    save32(w, &(db.len() as u32));
    save_bytes(w, db);
}
