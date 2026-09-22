use anyhow::Result;
use plist::Value;

pub struct PlistApi;

impl PlistApi {
    pub fn parse_plist_response(&self, data: &[u8]) -> Result<Value> {
        let val = plist::from_bytes(data)?;
        Ok(val)
    }
}
