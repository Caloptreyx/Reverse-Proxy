//! Validation for user supplied nginx snippets (`advanced_config`).
//!
//! Snippets run inside the NPM server block. Only the directives in
//! [`ALLOWED_DIRECTIVES`] may appear; everything else is rejected, including
//! every directive that reads or writes files on the proxy host and every
//! directive that could send a request somewhere other than the server's
//! allocation. The snippet is tokenized the way nginx does it (quotes,
//! escapes, `#` comments, `${`), so quoting a directive name or hiding it
//! behind a comment doesn't get past the check.
use super::marker::MARKER_PREFIX;

pub const MAX_LENGTH: usize = 4096;

/// Directives a snippet may use: headers, timeouts, buffering, size limits,
/// compression, IP allow/deny, rewrites and `location`/`if` blocks. Nothing
/// here takes a file path or picks an upstream: no `proxy_pass` or other
/// `*_pass`, no subrequests (`mirror`, `auth_request`, `error_page`), and no
/// `set`, because NPM's default location proxies to
/// `$forward_scheme://$server:$port`, set just before the snippet.
pub const ALLOWED_DIRECTIVES: &[&str] = &[
    "add_header",
    "add_trailer",
    "allow",
    "break",
    "charset",
    "chunked_transfer_encoding",
    "client_body_buffer_size",
    "client_body_timeout",
    "client_header_buffer_size",
    "client_header_timeout",
    "client_max_body_size",
    "default_type",
    "deny",
    "etag",
    "expires",
    "gzip",
    "gzip_comp_level",
    "gzip_disable",
    "gzip_min_length",
    "gzip_proxied",
    "gzip_types",
    "gzip_vary",
    "if",
    "if_modified_since",
    "ignore_invalid_headers",
    "keepalive_requests",
    "keepalive_timeout",
    "large_client_header_buffers",
    "location",
    "more_clear_headers",
    "more_clear_input_headers",
    "more_set_headers",
    "more_set_input_headers",
    "proxy_buffer_size",
    "proxy_buffering",
    "proxy_buffers",
    "proxy_busy_buffers_size",
    "proxy_connect_timeout",
    "proxy_cookie_domain",
    "proxy_cookie_flags",
    "proxy_cookie_path",
    "proxy_hide_header",
    "proxy_http_version",
    "proxy_ignore_headers",
    "proxy_intercept_errors",
    "proxy_max_temp_file_size",
    "proxy_method",
    "proxy_next_upstream",
    "proxy_next_upstream_timeout",
    "proxy_next_upstream_tries",
    "proxy_pass_header",
    "proxy_pass_request_body",
    "proxy_pass_request_headers",
    "proxy_read_timeout",
    "proxy_redirect",
    "proxy_request_buffering",
    "proxy_send_timeout",
    "proxy_set_body",
    "proxy_set_header",
    "proxy_ssl_name",
    "proxy_ssl_server_name",
    "real_ip_header",
    "real_ip_recursive",
    "return",
    "rewrite",
    "satisfy",
    "send_timeout",
    "server_tokens",
    "set_real_ip_from",
    "sub_filter",
    "sub_filter_last_modified",
    "sub_filter_once",
    "sub_filter_types",
    "underscores_in_headers",
];

/// Reads one token starting at `first`, following nginx's
/// `ngx_conf_read_token`: quotes may only open a token, `\` escapes the next
/// character, `{` right after `$` is part of the token (`${var}`), and `#` or
/// `}` inside a word are plain characters. Returns the token as nginx sees it
/// (quotes removed, `\"`, `\'`, `\\`, `\t`, `\r`, `\n` unescaped).
fn read_token(
    first: char,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<String, String> {
    const UNCLOSED_QUOTE: &str = "the custom nginx configuration has an unclosed quote";
    let mut raw = String::new();

    if let quote @ ('"' | '\'') = first {
        loop {
            match chars.next().ok_or(UNCLOSED_QUOTE)? {
                '\\' => {
                    raw.push('\\');
                    raw.push(chars.next().ok_or(UNCLOSED_QUOTE)?);
                }
                c if c == quote => break,
                c => raw.push(c),
            }
        }

        // nginx requires a separator right after a closing quote
        match chars.peek() {
            None | Some(' ' | '\t' | '\r' | '\n' | ';' | '{') => {}
            Some(')') => {
                chars.next();
            }
            Some(c) => {
                return Err(format!(
                    "unexpected `{c}` after a quote in the custom nginx configuration"
                ));
            }
        }
        return Ok(unescape(&raw));
    }

    let mut c = first;
    let mut variable = false;
    loop {
        match c {
            '{' if variable => raw.push(c),
            '\\' => {
                variable = false;
                raw.push(c);
                raw.push(
                    chars
                        .next()
                        .ok_or("the custom nginx configuration may not end with a `\\`")?,
                );
            }
            _ => {
                variable = c == '$';
                raw.push(c);
            }
        }

        // whitespace, `;` and `{` end the token and are left for the
        // statement parser; a `{` right after `$` belongs to the token
        match chars.peek() {
            None | Some(' ' | '\t' | '\r' | '\n' | ';') => break,
            Some('{') if !variable => break,
            Some(&next) => {
                chars.next();
                c = next;
            }
        }
    }

    Ok(unescape(&raw))
}

/// nginx's unescaping of a finished token. Unknown escapes keep the `\`.
fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(escaped @ ('"' | '\'' | '\\')) => out.push(escaped),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The directive name of every statement in `config`, in order. Fails on
/// anything nginx would parse differently from a closed list of statements:
/// unbalanced braces, unclosed quotes, a statement without its `;`.
fn directive_names(config: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut statement_started = false;
    let mut depth: usize = 0;
    let mut chars = config.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {}
            '#' => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            ';' | '{' => {
                if !statement_started {
                    return Err(format!(
                        "unexpected `{c}` in the custom nginx configuration"
                    ));
                }
                statement_started = false;
                if c == '{' {
                    depth += 1;
                }
            }
            '}' => {
                if statement_started {
                    return Err("unexpected `}` in the custom nginx configuration".into());
                }
                depth = depth
                    .checked_sub(1)
                    .ok_or("the custom nginx configuration has an unmatched `}`")?;
            }
            _ => {
                let token = read_token(c, &mut chars)?;
                if !statement_started {
                    names.push(token);
                    statement_started = true;
                }
            }
        }
    }

    if statement_started {
        return Err("the custom nginx configuration has a statement without a closing `;`".into());
    }
    if depth != 0 {
        return Err("the custom nginx configuration has an unclosed `{`".into());
    }

    Ok(names)
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

    for name in directive_names(config)? {
        if !ALLOWED_DIRECTIVES.contains(&name.as_str()) {
            return Err(format!(
                "the `{}` directive is not allowed in the custom nginx configuration",
                name.escape_debug()
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
        for config in [
            "if ($request_method = POST) { return 405; }",
            "if ($http_user_agent ~* \"bot\") { return 403; }",
            "add_header X-Host ${host}-x;",
            "location ~* \\.(png|jpg)$ { expires 30d; }",
            "proxy_set_header Upgrade $http_upgrade;\nproxy_set_header Connection \"upgrade\";",
            "add_header 'X-Frame-Options' 'DENY' always;",
            "\"add_header\" X 1;",
        ] {
            assert!(validate(config).is_ok(), "{config}");
        }
    }

    #[test]
    fn rejects_file_access_and_scripting() {
        for config in [
            "location /x { alias /data/; }",
            "root /etc;",
            "include /data/nginx/*.conf;",
            "content_by_lua_block { ngx.say(1) }",
            "access_log /tmp/x;",
            "  SSL_CERTIFICATE_KEY /x;",
            "proxy_store /data/nginx/proxy_host/x.conf;",
            "proxy_store on;",
            "fastcgi_store on;",
            "uwsgi_store /tmp/x;",
            "scgi_store /tmp/x;",
            "proxy_temp_path /data;",
            "error_page 404 /x;",
            "try_files $uri =404;",
            "location / { proxy_set_header X 1; proxy_store on; }",
        ] {
            assert!(validate(config).is_err(), "{config}");
        }
    }

    #[test]
    fn rejects_choosing_the_upstream() {
        for config in [
            "proxy_pass http://127.0.0.1:81;",
            "location / { proxy_pass http://npm:81; }",
            "location /api { proxy_pass $forward_scheme://$server:$port; }",
            "if ($request_method = POST) { proxy_pass http://10.0.0.1; }",
            "\"proxy_pass\" http://169.254.169.254;",
            "'proxy_pass' http://x;",
            "prox\\y_pass http://x;",
            "PROXY_PASS http://x;",
            "add_header X 1;proxy_pass http://x;",
            "location / {}proxy_pass http://x;",
            // NPM's default location proxies to these variables
            "set $server 127.0.0.1;",
            "set $port 81;",
            "set $forward_scheme https;",
            "if ($host) { set $server \"admin\"; }",
            "\"set\" $server x;",
            // other upstream modules
            "fastcgi_pass 127.0.0.1:9000;",
            "uwsgi_pass 127.0.0.1:3031;",
            "scgi_pass 127.0.0.1:4000;",
            "grpc_pass grpc://127.0.0.1:50051;",
            "memcached_pass 127.0.0.1:11211;",
            "upstream x { server 127.0.0.1:81; }",
            "resolver 127.0.0.1;",
            // subrequests
            "mirror /m;",
            "auth_request /auth;",
            "error_page 404 = http://127.0.0.1:81/;",
            "location /m { internal; proxy_pass http://127.0.0.1:81; }",
            "ssi on;",
            "add_after_body /x;",
        ] {
            assert!(validate(config).is_err(), "{config}");
        }
    }

    #[test]
    fn header_passthrough_is_not_an_upstream() {
        for config in [
            "proxy_pass_header Server;",
            "proxy_pass_request_body off;",
            "proxy_pass_request_headers on;",
        ] {
            assert!(validate(config).is_ok(), "{config}");
        }
    }

    #[test]
    fn quoting_escaping_and_comments_do_not_bypass_the_allowlist() {
        for config in [
            // quoted directive names
            "\"root\" /etc;",
            "'proxy_store' on;",
            "location / { \"alias\" /data/; }",
            // `#` inside a word is not a comment for nginx
            "client_max_body_size 1m#;\nroot /etc;",
            // a quote spanning lines hides a `#` from a line-based stripper
            "add_header X \"a\n# \";root /etc;",
            // an escaped quote does not close the string
            "add_header X \"a\\\" # \";proxy_store on;",
            // `}` right before a name, `;` right after a value
            "location / {return 200;}proxy_store on;",
            "add_header X 1;proxy_store on;",
            // escapes inside a name
            "ro\\ot /etc;",
            "\"ro\\ot\" /etc;",
            // unicode lookalikes and case
            "Root /etc;",
            "r\u{043E}ot /etc;",
        ] {
            assert!(validate(config).is_err(), "{config}");
        }
    }

    #[test]
    fn rejects_snippets_that_leak_into_the_surrounding_config() {
        for config in [
            "add_header X \"unclosed;",
            "add_header X 1",
            "add_header X 1 \\",
            "location / {",
            "}",
            "add_header X 1; }",
            "return 200 }",
            ";",
            "add_header X \"a\"b;",
        ] {
            assert!(validate(config).is_err(), "{config}");
        }
    }

    #[test]
    fn comments_and_quotes_do_not_trigger_rules() {
        assert!(validate("# alias /data/\nclient_max_body_size 1m;").is_ok());
        assert!(validate("add_header X-Note \"# root is fine here\";").is_ok());
        assert!(validate("add_header X-Note \"a; root /etc;\";").is_ok());
        assert!(validate("add_header X 1; # }").is_ok());
    }

    #[test]
    fn rejects_marker_and_length() {
        assert!(validate(&format!("{MARKER_PREFIX} instance=x proxy=y")).is_err());
        assert!(validate(&"a".repeat(MAX_LENGTH + 1)).is_err());
    }

    #[test]
    fn compose_puts_marker_first() {
        assert_eq!(compose_advanced_config("# m", ""), "# m");
        assert_eq!(compose_advanced_config("# m", "a 1;"), "# m\na 1;");
    }
}
