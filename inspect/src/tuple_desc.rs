use std::collections::HashMap;

use crate::tuple::Oid;
use serde::Deserialize;

pub type TupleDescriptorMap = HashMap<String, TupleDescriptor>;

#[derive(Deserialize, Debug)]
pub enum TypeOutput {
    #[serde(rename = "boolout")]
    Bool,

    #[serde(rename = "int2out")]
    Int2,
    #[serde(rename = "int4out")]
    Int4,
    #[serde(rename = "int8out")]
    Int8,

    #[serde(rename = "bpcharout")]
    Bpchar,
    #[serde(rename = "textout")]
    Text,
    #[serde(rename = "varcharout")]
    Varchar,

    #[serde(rename = "float4out")]
    Float4,
    #[serde(rename = "float8out")]
    Float8,

    #[serde(rename = "date_out")]
    Date,
    #[serde(rename = "time_out")]
    Time,
    #[serde(rename = "timestamptz_out")]
    Timestamptz,
    #[serde(rename = "timestamp_out")]
    Timestamp,
    #[serde(rename = "timetz_out")]
    Timetz,

    #[serde(rename = "uuid_out")]
    Uuid,
    #[serde(rename = "jsonb_out")]
    Jsonb,
}

#[derive(Deserialize)]
pub struct TupleDescriptor {
    pub relname: String,
    #[serde(rename = "tdtypeid")]
    pub type_id: u32,
    #[serde(rename = "tdtypmod")]
    pub type_mod: i32,
    #[serde(rename = "attrs")]
    pub attributes: Vec<Attribute>,
}

#[derive(Deserialize)]
pub struct Attribute {
    #[serde(rename = "attname")]
    pub name: String,
//    #[serde(rename = "atttypid")]
//    pub type_id: u32,
    #[serde(rename = "atttypoutput")]
    pub type_output: TypeOutput,
    #[serde(rename = "attbyval")]
    pub by_val: bool,
    #[serde(rename = "attispackable")]
    pub is_packable: bool,
    #[serde(rename = "atthasmissing")]
    pub has_missing: bool,
    #[serde(rename = "attisdropped")]
    pub is_dropped: bool,
    #[serde(rename = "attisprimary")]
    pub is_primary: bool,
    #[serde(rename = "attalignby")]
    pub align_by: u8,
}


#[cfg(test)]
mod tests {
    use crate::tuple_desc::TupleDescriptorMap;

    #[test]
    fn test_deserialise_tuple_desc() {
        let tuple_descs: TupleDescriptorMap =
            serde_json::from_str(include_str!("../assets/tuple_descriptor_test.json")).unwrap();
        assert_eq!(tuple_descs.len(), 2);
    }

    #[test]
    fn test_deform() {
        let tuple_descs: TupleDescriptorMap =
            serde_json::from_str(include_str!("../assets/tuple_descriptor_test.json")).unwrap();
        let tuple = &include_bytes!("../assets/page_two_tuples")[8160..8160 + 28];
        // deform_tuple(tuple_descs["16462"] (tuple);
    }
}
