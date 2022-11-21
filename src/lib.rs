mod s3_compatible_signing_client;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use s3_compatible_signing_client::{PresignedMultipartParameters, S3CompatibleSigningClient};
use serde::Deserialize;
use url::Url;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackblazeAuthResponse {
    // absolute_minimum_part_size: i64,
    // authorization_token: String,
    // api_url: String,
    // download_url: String,
    // recommended_part_size: i64,
    s3_api_url: String,
}

fn region_from_s3_api_url(s3_api_url: &str) -> Option<&str> {
    s3_api_url.split('.').nth(1)
}

async fn authorise_backblaze_b2<'a>(
    s3_compatible_account_id: &str,
    s3_compatible_account_auth_token: &str,
) -> Option<(String, String)> {
    let mut headers_map = HeaderMap::new();
    let combined_credential_value_base64 =
        format!("{s3_compatible_account_id}:{s3_compatible_account_auth_token}");
    let authorisation_credentials =
        base64::encode_config(combined_credential_value_base64, base64::URL_SAFE);
    let header_value = format!("Basic {authorisation_credentials}");
    headers_map.insert(AUTHORIZATION, HeaderValue::from_str(&header_value).unwrap());
    let client = reqwest::Client::new();
    let url = "https://api.backblazeb2.com/b2api/v2/b2_authorize_account";
    let result = match client.get(url).headers(headers_map).send().await {
        Ok(res) => res,
        Err(error) => panic!("Error: {error}"),
    };
    match result.json::<BackblazeAuthResponse>().await {
        Ok(value) => {
            let s3_api_url = match Url::parse(&value.s3_api_url) {
                Ok(value) => value,
                Err(_) => {
                    console_log!("Unable to parse S3 API URL");
                    return None;
                }
            };
            let endpoint = match s3_api_url.domain() {
                Some(value) => value,
                None => {
                    console_log!("Unable to parse S3 endpoint");
                    return None;
                }
            };
            let region = match region_from_s3_api_url(endpoint) {
                Some(value) => value,
                None => {
                    console_log!("Unable to infer S3 region");
                    return None;
                }
            };
            Some((endpoint.to_string(), region.to_string()))
        }
        Err(_) => {
            console_log!("Error getting auth from backblaze");
            None
        }
    }
}

#[wasm_bindgen]
pub async fn presigned_get_url(
    key: &str,
    bucket_name: &str,
    expiry: u32,
    s3_compatible_account_id: &str,
    s3_compatible_account_auth_token: &str,
    session_token: &str,
) -> String {
    if let Some((endpoint, region)) =
        authorise_backblaze_b2(s3_compatible_account_id, s3_compatible_account_auth_token).await
    {
        let signing_client = S3CompatibleSigningClient::new(
            s3_compatible_account_id,
            s3_compatible_account_auth_token,
            &endpoint,
            &region,
            session_token,
        );
        signing_client.presigned_get_url(bucket_name, key, expiry)
    } else {
        String::from("")
    }
}

#[wasm_bindgen]
pub async fn presigned_put_url(
    key: &str,
    bucket_name: &str,
    expiry: u32,
    s3_compatible_account_id: &str,
    s3_compatible_account_auth_token: &str,
    session_token: &str,
) -> String {
    if let Some((endpoint, region)) =
        authorise_backblaze_b2(s3_compatible_account_id, s3_compatible_account_auth_token).await
    {
        let signing_client = S3CompatibleSigningClient::new(
            s3_compatible_account_id,
            s3_compatible_account_auth_token,
            &endpoint,
            &region,
            session_token,
        );
        signing_client.presigned_put_url(bucket_name, key, expiry)
    } else {
        String::from("")
    }
}

#[wasm_bindgen]
pub async fn presigned_multipart_put_url(
    key: &str,
    bucket_name: &str,
    expiry: u32,
    parts: u32,
    upload_id: &str,
    s3_compatible_account_id: &str,
    s3_compatible_account_auth_token: &str,
    session_token: &str,
) -> String {
    if let Some((endpoint, region)) =
        authorise_backblaze_b2(s3_compatible_account_id, s3_compatible_account_auth_token).await
    {
        let signing_client = S3CompatibleSigningClient::new(
            s3_compatible_account_id,
            s3_compatible_account_auth_token,
            &endpoint,
            &region,
            session_token,
        );
        let data = PresignedMultipartParameters {
            bucket: bucket_name,
            key,
            parts,
            upload_id,
            expiry,
        };
        let urls = signing_client.presigned_multipart_put_url(&data);
        serde_json::to_string(&urls).unwrap()
    } else {
        String::from("")
    }
}
