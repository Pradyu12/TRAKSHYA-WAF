use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: RwLock<State>,
    failure_count: RwLock<u32>,
    success_count: RwLock<u32>,
    last_failure: RwLock<Option<Instant>>,
    config: BreakerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakerConfig {
    pub failure_threshold: u32,
    pub recovery_timeout_secs: u64,
    pub half_open_max_requests: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout_secs: 30,
            half_open_max_requests: 3,
        }
    }
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            state: RwLock::new(State::Closed),
            failure_count: RwLock::new(0),
            success_count: RwLock::new(0),
            last_failure: RwLock::new(None),
            config,
        }
    }

    pub async fn is_allowed(&self) -> bool {
        self.is_request_allowed().await
    }

    pub async fn is_request_allowed(&self) -> bool {
        let mut state = self.state.write().await;
        match *state {
            State::Closed => true,
            State::Open => {
                if let Some(time) = *self.last_failure.read().await {
                    if time.elapsed() > Duration::from_secs(self.config.recovery_timeout_secs) {
                        *state = State::HalfOpen;
                        *self.success_count.write().await = 0;
                        return true;
                    }
                }
                false
            }
            State::HalfOpen => {
                let successes = *self.success_count.read().await;
                if successes < self.config.half_open_max_requests {
                    true
                } else {
                    *state = State::Closed;
                    *self.failure_count.write().await = 0;
                    true
                }
            }
        }
    }

    pub async fn record_success(&self) {
        let mut state = self.state.write().await;
        if *state == State::HalfOpen {
            let mut successes = self.success_count.write().await;
            *successes += 1;
            if *successes >= self.config.half_open_max_requests {
                *state = State::Closed;
                *self.failure_count.write().await = 0;
                *successes = 0;
            }
        } else {
            *self.failure_count.write().await = 0;
        }
    }

    pub async fn record_failure(&self) {
        let mut failures = self.failure_count.write().await;
        *failures += 1;

        if *failures >= self.config.failure_threshold {
            *self.last_failure.write().await = Some(Instant::now());
            *self.state.write().await = State::Open;
        }
    }

    pub async fn state(&self) -> State {
        *self.state.read().await
    }
}
