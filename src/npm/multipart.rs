/// Hand-rolled `multipart/form-data` body - the workspace `reqwest` has no
/// `multipart` feature, and NPM's certificate endpoints require real file
/// fields (a `filename` in the disposition) rather than plain form fields.
pub struct MultipartBody {
    boundary: String,
    parts: Vec<(String, String, Vec<u8>)>, // (name, filename, content)
}

impl MultipartBody {
    pub fn new() -> Self {
        Self {
            boundary: format!("calagopus-{}", uuid::Uuid::new_v4().simple()),
            parts: Vec::new(),
        }
    }

    pub fn file(mut self, name: &str, filename: &str, content: impl Into<Vec<u8>>) -> Self {
        self.parts
            .push((name.to_string(), filename.to_string(), content.into()));
        self
    }

    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    pub fn build(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, filename, content) in &self.parts {
            body.extend_from_slice(
                format!(
                    "--{}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
                    self.boundary, name, filename
                )
                .as_bytes(),
            );
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_multipart() {
        let body = MultipartBody::new()
            .file("certificate", "cert.pem", b"CERTDATA".to_vec())
            .file("certificate_key", "key.pem", b"KEYDATA".to_vec());

        let boundary = body.boundary.clone();
        let bytes = body.build();
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.starts_with(&format!("--{boundary}\r\n")));
        assert!(text.ends_with(&format!("--{boundary}--\r\n")));
        assert!(text.contains("name=\"certificate\"; filename=\"cert.pem\""));
        assert!(text.contains("name=\"certificate_key\"; filename=\"key.pem\""));
        assert!(text.contains("\r\n\r\nCERTDATA\r\n"));
        assert!(text.contains("\r\n\r\nKEYDATA\r\n"));
        assert_eq!(
            body.content_type(),
            format!("multipart/form-data; boundary={boundary}")
        );
        // two parts + final boundary = 3 boundary lines
        assert_eq!(text.matches(&format!("--{boundary}")).count(), 3);
    }
}
