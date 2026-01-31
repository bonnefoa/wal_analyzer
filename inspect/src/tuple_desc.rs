use std::collections::HashMap;

use crate::tuple::Oid;
use serde::Deserialize;

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

impl TupleDescriptor {
    fn deform_tuple(&self, data: &[u8]) {}
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::tuple_desc::TupleDescriptor;

    #[test]
    fn test_deserialise_tuple_desc() {
        let tuple_descs: HashMap<u32, TupleDescriptor> =
            serde_json::from_str(include_str!("../assets/tuple_descriptor_test.json")).unwrap();
        assert_eq!(tuple_descs.len(), 2);
    }

    #[test]
    fn test_deform() {
        let tuple_desc: HashMap<u32, TupleDescriptor> =
            serde_json::from_str(include_str!("../assets/tuple_descriptor_test.json")).unwrap();
        let tuple = &include_bytes!("../assets/page_two_tuples")[8160..8160 + 28];
    }
}
