use chrono::{DateTime, Utc};
use hmac::{Mac, SimpleHmac};
use sha2::{Digest, Sha256};
use url::Url;

type HmacSha256 = SimpleHmac<Sha256>;

pub struct S3CompatibleSigningClient {
    account_id: String,
    account_auth_token: String,
    endpoint: String,
    region: String,
    session_token: String,
}

pub struct PresignedMultipartParameters<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub parts: u32,
    pub upload_id: &'a str,
    pub expiry: u32,
}

impl S3CompatibleSigningClient {
    pub fn new(
        account_id: &str,
        account_auth_token: &str,
        endpoint: &str,
        region: &str,
        session_token: &str,
    ) -> S3CompatibleSigningClient {
        S3CompatibleSigningClient {
            account_id: account_id.into(),
            account_auth_token: account_auth_token.into(),
            endpoint: endpoint.into(),
            region: region.into(),
            session_token: session_token.into(),
        }
    }

    fn hmac_sha256_sign<'a>(key: &'a [u8], message: &'a [u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("Error parsing HMAC_SHA256 key");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    fn get_canonical_request(&self, key: &str, method: &str, url: &Url) -> Option<String> {
        let uri = format!("/{key}");
        let query_string = if let Some(value) = url.query() {
            value
        } else {
            ""
        };
        let host = match url.domain() {
            Some(value) => value,
            None => return None,
        };
        let headers = format!("host:{host}");
        let signed_headers = "host";

        Some(format!(
            "{method}\n{uri}\n{query_string}\n{headers}\n\n{signed_headers}\nUNSIGNED-PAYLOAD"
        ))
    }

    fn get_signing_key(&self, date: &str, string_to_sign: &str) -> String {
        let secret = &self.account_auth_token;
        let key_date = Self::hmac_sha256_sign(format!("AWS4{secret}").as_bytes(), date.as_bytes());
        let key_region = Self::hmac_sha256_sign(key_date.as_slice(), self.region.as_bytes());
        let key_service = Self::hmac_sha256_sign(key_region.as_slice(), b"s3");
        let key_signing = Self::hmac_sha256_sign(key_service.as_slice(), b"aws4_request");
        let signature = Self::hmac_sha256_sign(key_signing.as_slice(), string_to_sign.as_bytes());
        hex::encode(signature)
    }

    fn get_string_to_sign(
        &self,
        canonical_request: &str,
        iso_date: &str,
        credential_scope: &str,
    ) -> String {
        let algorithm = "AWS4-HMAC-SHA256";
        let mut hasher = Sha256::new();
        hasher.update(canonical_request);
        let canonical_request_hash = hex::encode(hasher.finalize());
        format!("{algorithm}\n{iso_date}\n{credential_scope}\n{canonical_request_hash}")
    }

    fn multipart_presigned_url(
        &self,
        data: &PresignedMultipartParameters,

        method: &str,
        time: &DateTime<Utc>,
    ) -> Vec<String> {
        let key = data.key;
        let iso_date = time.format("%Y%m%dT%H%M%SZ").to_string();
        let date = time.format("%Y%m%d").to_string();
        let credential_scope = format!("{date}/{}/s3/aws4_request", &self.region);
        let mut urls_vector: Vec<String> = Vec::new();
        for part in 1..(data.parts + 1) {
            let mut url =
                match Url::parse(&format!("https://{}.{}/{key}", data.bucket, &self.endpoint)) {
                    Ok(value) => value,
                    Err(_) => {
                        panic!("Error parsing url")
                    }
                };

            url.query_pairs_mut()
                .append_pair("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
                .append_pair("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
                .append_pair(
                    "X-Amz-Credential",
                    &format!("{}/{credential_scope}", &self.account_id),
                )
                .append_pair("X-Amz-Date", &iso_date)
                .append_pair("X-Amz-Expires", &data.expiry.to_string())
                .append_pair("X-Amz-Security-Token", &self.session_token)
                .append_pair("X-Amz-SignedHeaders", "host")
                .append_pair("partNumber", &part.to_string())
                .append_pair("uploadId", data.upload_id)
                .append_pair("x-id", "UploadPart");
            let canonical_request = match Self::get_canonical_request(self, key, method, &url) {
                Some(value) => value,
                None => return Vec::new(),
            };
            let string_to_sign =
                Self::get_string_to_sign(self, &canonical_request, &iso_date, &credential_scope);
            let signature = Self::get_signing_key(self, &date, &string_to_sign);
            url.query_pairs_mut()
                .append_pair("X-Amz-Signature", &signature);
            urls_vector.push(url.to_string());
        }
        urls_vector
    }

    fn presigned_url(
        &self,
        bucket: &str,
        key: &str,
        method: &str,
        time: &DateTime<Utc>,
        expiry: u32,
    ) -> String {
        let iso_date = time.format("%Y%m%dT%H%M%SZ").to_string();
        let date = time.format("%Y%m%d").to_string();
        let credential_scope = format!("{date}/{}/s3/aws4_request", &self.region);
        let mut url = match Url::parse(&format!("https://{bucket}.{}/{key}", &self.endpoint)) {
            Ok(value) => value,
            Err(_) => {
                panic!("Error parsing url")
            }
        };
        url.query_pairs_mut()
            .append_pair("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
            .append_pair("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
            .append_pair(
                "X-Amz-Credential",
                &format!("{}/{credential_scope}", &self.account_id),
            )
            .append_pair("X-Amz-Date", &iso_date)
            .append_pair("X-Amz-Expires", &expiry.to_string())
            .append_pair("X-Amz-Security-Token", &self.session_token)
            .append_pair("X-Amz-SignedHeaders", "host")
            .append_pair("x-id", "PutObject");

        let canonical_request = match Self::get_canonical_request(self, key, method, &url) {
            Some(value) => value,
            None => return String::new(),
        };
        let string_to_sign =
            Self::get_string_to_sign(self, &canonical_request, &iso_date, &credential_scope);
        let signature = Self::get_signing_key(self, &date, &string_to_sign);
        url.query_pairs_mut()
            .append_pair("X-Amz-Signature", &signature);
        url.to_string()
    }

    pub fn presigned_get_url(&self, bucket: &str, key: &str, expiry: u32) -> String {
        let time = Utc::now();
        Self::presigned_url(self, bucket, key, "GET", &time, expiry)
    }

    pub fn presigned_put_url(&self, bucket: &str, key: &str, expiry: u32) -> String {
        let time = Utc::now();

        Self::presigned_url(self, bucket, key, "PUT", &time, expiry)
    }

    pub fn presigned_multipart_put_url(&self, data: &PresignedMultipartParameters) -> Vec<String> {
        let time = Utc::now();
        Self::multipart_presigned_url(self, data, "PUT", &time)
    }
}

#[cfg(test)]
mod tests {

    use crate::S3CompatibleSigningClient;
    use chrono::DateTime;
    use chrono::Utc;
    use url::Url;

    #[test]
    pub fn test_get_canonical_request() {
        let id = "AKIDEXAMPLE";
        let key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let endpoint = "s3.amazonaws.com";
        let region = "us.east-1";
        let session_token = "session-claqbxlfv0000ix0lx6inf7sd";
        let signing_client =
            S3CompatibleSigningClient::new(id, key, endpoint, region, session_token);
        let url =  Url::parse("https://example-bucket.s3.us-east-1.amazonaws.com/my-movie.m2ts?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=600&X-Amz-Security-Token=session-claqbxlfv0000ix0lx6inf7sd&X-Amz-SignedHeaders=host&x-id=PutObject").unwrap();
        let canonical_request = S3CompatibleSigningClient::get_canonical_request(
            &signing_client,
            "my-movie.m2ts",
            "PUT",
            &url,
        );
        assert_eq!(
            canonical_request,
            Some(
                "PUT
/my-movie.m2ts
X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=600&X-Amz-Security-Token=session-claqbxlfv0000ix0lx6inf7sd&X-Amz-SignedHeaders=host&x-id=PutObject
host:example-bucket.s3.us-east-1.amazonaws.com

host
UNSIGNED-PAYLOAD"
                    .to_string()
            )
        );
    }

    #[test]
    pub fn test_get_signing_key() {
        let id = "AKIDEXAMPLE";
        let key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let endpoint = "s3.amazonaws.com";
        let region = "us.east-1";
        let session_token = "session-claqbxlfv0000ix0lx6inf7sd";
        let signing_client =
            S3CompatibleSigningClient::new(id, key, endpoint, region, session_token);
        let signing_key = S3CompatibleSigningClient::get_signing_key(
            &signing_client,
            "20150830T123600Z",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            signing_key,
            "5664532906938a35d4cbe22f8ca6147a580e7350bd35b3f7ab00e6fafaf92848".to_string()
        );
    }

    #[test]
    pub fn test_get_string_to_sign() {
        let id = "AKIDEXAMPLE";
        let key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let endpoint = "s3.amazonaws.com";
        let region = "us.east-1";
        let session_token = "session-claqbxlfv0000ix0lx6inf7sd";
        let signing_client =
            S3CompatibleSigningClient::new(id, key, endpoint, region, session_token);

        let iso_date = "20150830T123600Z";
        let credential_scope = "20150830/us-east-01/s3/aws4_request";
        let canonical_request = "PUT
/my-movie.m2ts
partNumber=1&uploadId=VCVsb2FkIElEIGZvciBlbZZpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZR
host:example-bucket.s3.us-east-1.amazonaws.com

host
UNSIGNED-PAYLOAD";

        let string_to_sign = S3CompatibleSigningClient::get_string_to_sign(
            &signing_client,
            canonical_request,
            iso_date,
            credential_scope,
        );
        assert_eq!(
            string_to_sign,
            "AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-01/s3/aws4_request
08090f4b3cfb7b8285239e2a25a5318736f3a961266ca5376ce239a0a78eb5a4"
                .to_string()
        );
    }

    #[test]
    pub fn test_hmac_sha256_sign() {
        let key_date = S3CompatibleSigningClient::hmac_sha256_sign(
            format!("AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").as_bytes(),
            b"20150830",
        );
        let key_region =
            S3CompatibleSigningClient::hmac_sha256_sign(key_date.as_slice(), b"us-east-1");
        let key_service =
            S3CompatibleSigningClient::hmac_sha256_sign(key_region.as_slice(), b"iam");
        let key_signing =
            S3CompatibleSigningClient::hmac_sha256_sign(key_service.as_slice(), b"aws4_request");
        assert_eq!(
            hex::encode(key_signing),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    pub fn test_presigned_url() {
        let id = "AKIDEXAMPLE";
        let key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let endpoint = "s3.amazonaws.com";
        let region = "us.east-1";
        let session_token = "session-claqbxlfv0000ix0lx6inf7sd";
        let signing_client =
            S3CompatibleSigningClient::new(id, key, endpoint, region, session_token);
        let time = DateTime::parse_from_rfc3339("2015-08-30T12:36:00Z")
            .unwrap()
            .with_timezone::<Utc>(&Utc);

        let bucket = "example-bucket";
        let key = "my-movie.m2ts";
        let method = "PUT";
        let expiry: u32 = 600;
        let url = S3CompatibleSigningClient::presigned_url(
            &signing_client,
            bucket,
            key,
            method,
            &time,
            expiry,
        );
        assert_eq!(
                url,
                "https://example-bucket.s3.amazonaws.com/my-movie.m2ts?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus.east-1%2Fs3%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=600&X-Amz-Security-Token=session-claqbxlfv0000ix0lx6inf7sd&X-Amz-SignedHeaders=host&x-id=PutObject&X-Amz-Signature=d055386ea21099e7680de0625f51155f19050922ad21c7e6774460ac7a27c518"
                    .to_string()
            );
    }
}
