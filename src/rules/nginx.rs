//! Validation for user supplied nginx snippets (`advanced_config`).
//!
//! Snippets run inside the NPM server block, so a denylist can only reduce
//! the risk, never remove it - the admin toggle that enables them says so.
use super::marker::MARKER_PREFIX;

pub const MAX_LENGTH: usize = 4096;

/// Directives that read or write files on the proxy, load code, or replace
/// settings NPM manages itself.
const FORBIDDEN_DIRECTIVES: &[&str] = &[
    "access_log",
    "alias",
    "auth_basic_user_file",
    "client_body_temp_path",
    "daemon",
    "env",
    "error_log",
    "error_page",
    "fastcgi_temp_path",
    "include",
    "listen",
    "load_module",
    "master_process",
    "pid",
    "proxy_temp_path",
    "root",
    "scgi_temp_path",
    "server_name",
    "ssl_certificate",
    "ssl_certificate_key",
    "ssl_password_file",
    "ssl_trusted_certificate",
    "ssl_client_certificate",
    "ssl_crl",
    "ssl_dhparam",
    "ssl_stapling_file",
    "uwsgi_temp_path",
    "user",
    "worker_processes",
];

/// Directive name prefixes/fragments that load scripting modules.
const FORBIDDEN_FRAGMENTS: &[&str] = &["lua", "perl", "js_"];

fn directive_forbidden(name: &str) -> bool {
    FORBIDDEN_DIRECTIVES.contains(&name)
        || FORBIDDEN_FRAGMENTS
            .iter()
            .any(|fragment| name.contains(fragment))
}

/// Strips `#` comments (outside of quotes) from one line.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (index, ch) in line.char_indices() {
        match (ch, quote) {
            ('\'' | '"', None) => quote = Some(ch),
            (c, Some(q)) if c == q => quote = None,
            ('#', None) => return &line[..index],
            _ => {}
        }
    }
    line
}

/// Normalizes and validates a snippet. Returns the trimmed snippet (empty
/// string = no custom config) or a readable reason.
pub fn validate(config: &str) -> Result<String, String> {
    let config = config.replace("\r\n", "\n");
    let config = config.trim();
    if config.is_empty() {
        return Ok(String::new());
    }

    if config.len() > MAX_LENGTH {
        return Err(format!(
            "the custom nginx configuration may not be longer than {MAX_LENGTH} characters"
        ));
    }

    if config.contains(MARKER_PREFIX) {
        return Err("the custom nginx configuration may not contain the ownership marker".into());
    }

    let code: String = config
        .lines()
        .map(strip_comment)
        .collect::<Vec<_>>()
        .join("\n");

    let mut depth: i32 = 0;
    for ch in code.chars() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return Err("the custom nginx configuration has an unmatched `}`".into());
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("the custom nginx configuration has an unclosed `{`".into());
    }

    // every statement starts after `;`, `{` or `}` - its first word is the
    // directive name
    for statement in code.split([';', '{', '}']) {
        let Some(name) = statement.split_whitespace().next() else {
            continue;
        };
        let name = name.to_lowercase();
        if directive_forbidden(&name) {
            return Err(format!(
                "the `{name}` directive is not allowed in the custom nginx configuration"
            ));
        }
    }

    Ok(config.to_string())
}

/// The full `advanced_config` for an NPM host: ownership marker first, then
/// the user's snippet.
pub fn compose_advanced_config(marker: &str, custom: &str) -> String {
    if custom.is_empty() {
        marker.to_string()
    } else {
        format!("{marker}\n{custom}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_ok() {
        assert_eq!(validate("  \n ").unwrap(), "");
    }

    #[test]
    fn accepts_harmless_directives() {
        let config = "client_max_body_size 50m;\nproxy_read_timeout 300s; # long polling\nlocation /api {\n  proxy_set_header X-Test 1;\n}";
        assert_eq!(validate(config).unwrap(), config);
    }

    #[test]
    fn rejects_file_access_and_scripting() {
        assert!(validate("location /x { alias /data/; }").is_err());
        assert!(validate("root /etc;").is_err());
        assert!(validate("include /data/nginx/*.conf;").is_err());
        assert!(validate("content_by_lua_block { ngx.say(1) }").is_err());
        assert!(validate("access_log /tmp/x;").is_err());
        assert!(validate("  SSL_CERTIFICATE_KEY /x;").is_err());
    }

    #[test]
    fn comments_and_quotes_do_not_hide_or_trigger_rules() {
        assert!(validate("# alias /data/\nclient_max_body_size 1m;").is_ok());
        assert!(validate("add_header X-Note \"# root is fine here\";").is_ok());
        assert!(validate("add_header X 1; # }").is_ok());
    }

    #[test]
    fn rejects_unbalanced_braces_marker_and_length() {
        assert!(validate("location / {").is_err());
        assert!(validate("}").is_err());
        assert!(validate(&format!("{MARKER_PREFIX} instance=x proxy=y")).is_err());
        assert!(validate(&"a".repeat(MAX_LENGTH + 1)).is_err());
    }

    #[test]
    fn compose_puts_marker_first() {
        assert_eq!(compose_advanced_config("# m", ""), "# m");
        assert_eq!(compose_advanced_config("# m", "a 1;"), "# m\na 1;");
    }
}
