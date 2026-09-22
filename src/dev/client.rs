use anyhow::Result;
use reqwest::blocking::Client;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct AnisetteCache;

pub struct DeveloperClient {
    pub client: Client,
    pub cached: Option<AnisetteCache>,
    pub cache_time: Option<Instant>,
}

impl DeveloperClient {
    pub fn get_cache(&mut self, force: bool) -> Result<AnisetteCache> {
        if !force {
            if let (Some(c), Some(t)) = (&self.cached, self.cache_time) {
                if t.elapsed() < Duration::from_secs(60) {
                    return Ok(c.clone());
                }
            }
        }
        
        let new_cache = AnisetteCache;
        self.cached = Some(new_cache.clone());
        self.cache_time = Some(Instant::now());
        Ok(new_cache)
    }

    pub fn send_request(&self, url: &str, body_bytes: Vec<u8>) -> Result<()> {
        let headers = reqwest::header::HeaderMap::new();
        let _resp = self
            .client
            .post(url)
            .headers(headers)
            .body(body_bytes)
            .send()?;
        Ok(())
    }
}
