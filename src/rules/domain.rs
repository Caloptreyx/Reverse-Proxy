use std::sync::LazyLock;

/// `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` - a single DNS label, 1-63 chars.
pub(crate) static LABEL_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("invalid label regex")
});

/// Normalizes (trims, strips a trailing dot, lowercases) and validates a
/// fully-qualified domain name. Returns the normalized domain or a readable
/// reason. Punycode IDN labels (`xn--...`) pass through as-is; non-ASCII
/// input is rejected.
pub fn validate_domain(domain: &str) -> Result<String, String> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();

    if domain.is_empty() {
        return Err("domain may not be empty".to_string());
    }
    if !domain.is_ascii() {
        return Err(
            "domain may only contain ASCII characters (use punycode for IDN domains)".to_string(),
        );
    }
    if domain.len() > 253 {
        return Err("domain may not be longer than 253 characters".to_string());
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err("domain must contain at least two labels".to_string());
    }
    for label in &labels {
        if !LABEL_REGEX.is_match(label) {
            return Err(format!(
                "label `{label}` is invalid: labels must be 1-63 characters of lowercase letters, numbers and dashes, and may not start or end with a dash"
            ));
        }
    }

    Ok(domain)
}

/// Whether `domain` equals `parent` or sits below it (`a.example.com` is
/// under `example.com`).
pub fn is_under(domain: &str, parent: &str) -> bool {
    domain == parent || domain.ends_with(&format!(".{parent}"))
}

/// Normalizes an allowed-suffix entry (`example.com`, `.example.com`,
/// `*.example.com` all mean "example.com or below"). `None` when the rest is
/// not a valid domain.
pub fn normalize_suffix(suffix: &str) -> Option<String> {
    let suffix = suffix.trim();
    let suffix = suffix.strip_prefix("*.").unwrap_or(suffix);
    validate_domain(suffix.trim_start_matches('.')).ok()
}

/// Whether `domain` is allowed by the suffix allowlist and the blocklist.
/// An empty `allowed` list allows everything.
pub fn domain_allowed(
    domain: &str,
    allowed: &[String],
    blocked: &[regex::Regex],
) -> Result<(), String> {
    if !allowed.is_empty()
        && !allowed
            .iter()
            .filter_map(|suffix| normalize_suffix(suffix))
            .any(|suffix| is_under(domain, &suffix))
    {
        return Err("this domain does not end in an allowed domain suffix".to_string());
    }

    if blocked.iter().any(|pattern| pattern.is_match(domain)) {
        return Err("this domain is not allowed".to_string());
    }

    Ok(())
}

/// Compiles case-insensitive blocklist patterns, skipping invalid ones (they
/// are rejected at write time by the settings route).
pub fn compile_patterns(patterns: &[String]) -> Vec<regex::Regex> {
    patterns
        .iter()
        .filter_map(|pattern| {
            regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_domain_accepts() {
        for valid in [
            "example.com",
            "play.example.com",
            "a.b.c.example.com",
            "xn--nxasmq6b.example.com",
            "0-0.example.com",
            &format!("{}.example.com", "a".repeat(61)),
        ] {
            assert_eq!(
                validate_domain(valid).as_deref(),
                Ok(valid),
                "{valid} should be valid"
            );
        }
        assert_eq!(
            validate_domain("  Play.Example.COM.  "),
            Ok("play.example.com".to_string())
        );
    }

    #[test]
    fn validate_domain_rejects() {
        for invalid in [
            "",
            "localhost",
            "example",
            "-a.example.com",
            "a-.example.com",
            "a..example.com",
            "*.example.com",
            "a_b.example.com",
            "exa mple.com",
            "münchen.example.com",
            &format!("{}.com", "a".repeat(64)),
            &format!("{}.com", "a".repeat(250)),
        ] {
            assert!(
                validate_domain(invalid).is_err(),
                "{invalid} should be invalid"
            );
        }
    }

    #[test]
    fn is_under_checks() {
        assert!(is_under("example.com", "example.com"));
        assert!(is_under("a.example.com", "example.com"));
        assert!(is_under("a.b.example.com", "example.com"));
        assert!(!is_under("notexample.com", "example.com"));
        assert!(!is_under("example.com.evil.com", "example.com"));
        assert!(!is_under("example.com", "a.example.com"));
    }

    #[test]
    fn suffix_normalization() {
        for input in ["example.com", " .Example.com. ", "*.example.com"] {
            assert_eq!(normalize_suffix(input).as_deref(), Some("example.com"));
        }
        assert_eq!(normalize_suffix("com"), None);
        assert_eq!(normalize_suffix("*.*.example.com"), None);
    }

    #[test]
    fn domain_allowed_checks() {
        let blocked = compile_patterns(&["^bad".to_string(), "vpn".to_string()]);
        let allowed = ["example.com".to_string(), "*.example.org".to_string()];

        assert!(domain_allowed("a.other.com", &[], &blocked).is_ok());
        assert!(domain_allowed("example.com", &allowed, &blocked).is_ok());
        assert!(domain_allowed("a.b.example.com", &allowed, &blocked).is_ok());
        assert!(domain_allowed("example.org", &allowed, &blocked).is_ok());
        assert!(domain_allowed("a.other.com", &allowed, &blocked).is_err());
        assert!(domain_allowed("notexample.com", &allowed, &blocked).is_err());
        assert!(domain_allowed("bad.example.com", &[], &blocked).is_err());
        assert!(domain_allowed("my-vpn.example.com", &[], &blocked).is_err());
        // blocklist is case-insensitive, domains arrive lowercased anyway
        assert!(domain_allowed("BAD.example.com", &[], &blocked).is_err());
    }
}
