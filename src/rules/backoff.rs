use chrono::{DateTime, Utc};
use std::time::Duration;

/// Backoff after the Nth failed issuance attempt (1-based). `None` after the
/// 4th failure - no more automatic retries.
pub const BACKOFF: [Duration; 4] = [
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
    Duration::from_secs(6 * 60 * 60),
    Duration::from_secs(24 * 60 * 60),
];

/// `attempts` is the failure count including the failure that just happened.
pub fn backoff_after_failure(attempts: i32) -> Option<Duration> {
    if attempts < 1 {
        return Some(BACKOFF[0]);
    }
    BACKOFF.get(attempts as usize - 1).copied()
}

/// DNS preflight retry interval: every 5 minutes for the first 24 hours after
/// creation, then hourly.
pub fn preflight_retry_interval(created: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    if now - created < chrono::Duration::hours(24) {
        Duration::from_secs(5 * 60)
    } else {
        Duration::from_secs(60 * 60)
    }
}

/// Let's Encrypt protection: issuance attempts allowed per hour across the
/// panel, and per domain per week.
pub const MAX_ISSUANCES_PER_HOUR: u32 = 10;
pub const MAX_ISSUANCES_PER_DOMAIN_PER_WEEK: u32 = 3;

/// Given issuance-ledger timestamps, computes the earliest moment a new
/// issuance is allowed. `None` when it may proceed immediately. Both windows
/// must have room; the returned instant is the later of the two unblock
/// times.
pub fn rate_limit_next_attempt(
    now: DateTime<Utc>,
    attempts_last_hour: &[DateTime<Utc>],
    domain_attempts_last_week: &[DateTime<Utc>],
    max_per_hour: u32,
    max_per_domain_week: u32,
) -> Option<DateTime<Utc>> {
    let mut next: Option<DateTime<Utc>> = None;

    if attempts_last_hour.len() >= max_per_hour as usize
        && let Some(oldest) = attempts_last_hour.iter().min()
    {
        next = Some(*oldest + chrono::Duration::hours(1));
    }

    if domain_attempts_last_week.len() >= max_per_domain_week as usize
        && let Some(oldest) = domain_attempts_last_week.iter().min()
    {
        let free_at = *oldest + chrono::Duration::days(7);
        next = Some(next.map_or(free_at, |n| n.max(free_at)));
    }

    // never suggest a time in the past
    next.filter(|n| *n > now).or(next.map(|_| now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn backoff_schedule() {
        assert_eq!(backoff_after_failure(1), Some(Duration::from_secs(900)));
        assert_eq!(backoff_after_failure(2), Some(Duration::from_secs(3600)));
        assert_eq!(backoff_after_failure(3), Some(Duration::from_secs(21600)));
        assert_eq!(backoff_after_failure(4), Some(Duration::from_secs(86400)));
        assert_eq!(backoff_after_failure(5), None);
    }

    #[test]
    fn preflight_interval_switches_after_a_day() {
        let created = Utc::now();
        assert_eq!(
            preflight_retry_interval(created, created + ChronoDuration::hours(2)),
            Duration::from_secs(300)
        );
        assert_eq!(
            preflight_retry_interval(created, created + ChronoDuration::hours(25)),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn rate_limit_allows_when_windows_have_room() {
        let now = Utc::now();
        assert_eq!(
            rate_limit_next_attempt(now, &[now], &[now, now], 10, 3),
            None
        );
    }

    #[test]
    fn rate_limit_global_window() {
        let now = Utc::now();
        let attempts: Vec<_> = (0..10)
            .map(|i| now - ChronoDuration::minutes(30 - i))
            .collect();
        let next = rate_limit_next_attempt(now, &attempts, &[], 10, 3).unwrap();
        // frees when the oldest attempt leaves the 1h window
        assert_eq!(next, attempts[0] + ChronoDuration::hours(1));
    }

    #[test]
    fn rate_limit_domain_window_wins_when_later() {
        let now = Utc::now();
        let global: Vec<_> = (0..10).map(|_| now - ChronoDuration::minutes(59)).collect();
        let domain: Vec<_> = (0..3).map(|_| now - ChronoDuration::days(6)).collect();
        let next = rate_limit_next_attempt(now, &global, &domain, 10, 3).unwrap();
        assert_eq!(next, domain[0] + ChronoDuration::days(7));
    }

    #[test]
    fn rate_limit_past_free_time_clamps_to_now() {
        let now = Utc::now();
        let old = now - ChronoDuration::days(8);
        let domain = vec![old; 3];
        assert_eq!(rate_limit_next_attempt(now, &[], &domain, 10, 3), Some(now));
    }
}
