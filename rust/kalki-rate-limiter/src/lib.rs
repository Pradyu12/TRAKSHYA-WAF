use dashmap::DashMap;
use std::time::{Duration, Instant};

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    buckets: DashMap<String, Bucket>,
    max_tokens: f64,
    refill_rate: f64,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32, burst_size: u32) -> Self {
        let max_tokens = burst_size as f64;
        let refill_rate = requests_per_minute as f64 / 60.0;

        Self {
            buckets: DashMap::new(),
            max_tokens,
            refill_rate,
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        let mut bucket = self.buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket {
                tokens: self.max_tokens,
                last_refill: Instant::now(),
            });

        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn reset(&self, key: &str) {
        self.buckets.remove(key);
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }
}
