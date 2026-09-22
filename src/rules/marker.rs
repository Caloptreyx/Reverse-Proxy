use uuid::Uuid;

/// Marker written into `advanced_config` of every proxy host we create so we
/// can prove ownership before mutating or deleting it.
pub const MARKER_PREFIX: &str = "# managed-by calagopus dev.caloptreyx.reverseproxy";

/// `nice_name` prefix for custom certificates we create on NPM.
pub const CERT_NICE_NAME_PREFIX: &str = "calagopus:";

pub fn build_marker(instance_id: &str, proxy_uuid: Uuid) -> String {
    format!("{MARKER_PREFIX} instance={instance_id} proxy={proxy_uuid}")
}

/// Parses `(instance_id, proxy_uuid)` out of an `advanced_config` value.
/// The marker may appear anywhere in the config (users may add their own
/// directives below it).
pub fn parse_marker(advanced_config: &str) -> Option<(String, Uuid)> {
    for line in advanced_config.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(MARKER_PREFIX) else {
            continue;
        };

        let mut instance_id = None;
        let mut proxy_uuid = None;
        for part in rest.split_whitespace() {
            if let Some(value) = part.strip_prefix("instance=") {
                instance_id = Some(value.to_string());
            } else if let Some(value) = part.strip_prefix("proxy=") {
                proxy_uuid = value.parse::<Uuid>().ok();
            }
        }

        if let (Some(instance_id), Some(proxy_uuid)) = (instance_id, proxy_uuid) {
            return Some((instance_id, proxy_uuid));
        }
    }

    None
}

/// Whether `advanced_config` carries our marker for this instance and proxy.
pub fn marker_matches(advanced_config: &str, instance_id: &str, proxy_uuid: Uuid) -> bool {
    parse_marker(advanced_config)
        .is_some_and(|(instance, uuid)| instance == instance_id && uuid == proxy_uuid)
}

pub fn cert_nice_name(instance_id: &str, proxy_uuid: Uuid) -> String {
    format!("{CERT_NICE_NAME_PREFIX}{instance_id}:{proxy_uuid}")
}

/// Whether a certificate `nice_name` belongs to this panel instance
/// (`calagopus:<instance_id>:<proxy uuid>`). Used for orphan detection; certs
/// from other instances are never considered ours.
pub fn is_owned_cert_nice_name(nice_name: &str, instance_id: &str) -> bool {
    let prefix = format!("{CERT_NICE_NAME_PREFIX}{instance_id}:");
    nice_name
        .strip_prefix(&prefix)
        .is_some_and(|rest| rest.parse::<Uuid>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_roundtrip() {
        let uuid = uuid::uuid!("11111111-2222-3333-4444-555555555555");
        let marker = build_marker("inst-1", uuid);
        assert_eq!(
            marker,
            "# managed-by calagopus dev.caloptreyx.reverseproxy instance=inst-1 proxy=11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(parse_marker(&marker), Some(("inst-1".to_string(), uuid)));
    }

    #[test]
    fn parse_marker_embedded_in_config() {
        let uuid = uuid::uuid!("11111111-2222-3333-4444-555555555555");
        let config = format!(
            "# comment\n{}\nproxy_set_header X-Test 1;\n",
            build_marker("abc", uuid)
        );
        assert_eq!(parse_marker(&config), Some(("abc".to_string(), uuid)));
        assert!(marker_matches(&config, "abc", uuid));
        assert!(!marker_matches(&config, "other", uuid));
        assert!(!marker_matches(&config, "abc", Uuid::nil()));
    }

    #[test]
    fn parse_marker_rejects_garbage() {
        for config in [
            "",
            "# managed-by calagopus dev.caloptreyx.reverseproxy",
            "# managed-by calagopus dev.caloptreyx.reverseproxy instance=x",
            "# managed-by calagopus dev.caloptreyx.reverseproxy instance=x proxy=not-a-uuid",
            "managed-by calagopus dev.caloptreyx.reverseproxy instance=x proxy=11111111-2222-3333-4444-555555555555",
        ] {
            assert_eq!(parse_marker(config), None, "{config} should not parse");
        }
    }

    #[test]
    fn cert_nice_name_matching() {
        let uuid = uuid::uuid!("11111111-2222-3333-4444-555555555555");
        let name = cert_nice_name("inst", uuid);
        assert_eq!(name, "calagopus:inst:11111111-2222-3333-4444-555555555555");
        assert!(is_owned_cert_nice_name(&name, "inst"));
        assert!(!is_owned_cert_nice_name(&name, "other"));
        assert!(!is_owned_cert_nice_name(
            "calagopus:inst:not-a-uuid",
            "inst"
        ));
        assert!(!is_owned_cert_nice_name("something else", "inst"));
        assert!(!is_owned_cert_nice_name("calagopus:inst:", "inst"));
    }
}
