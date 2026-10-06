use anyhow::Result;
use plist::Value;

#[allow(dead_code)]
pub struct PlistApi;

#[allow(dead_code)]
impl PlistApi {
    pub fn parse_plist_response(&self, data: &[u8]) -> Result<Value> {
        let val = plist::from_bytes(data)?;
        Ok(val)
    }
}
