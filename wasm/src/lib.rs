//! WASM SDK for Uniwallet
//! Exposes functions for browser integration, including wallet creation via HTTP and WebAuthn-based flows.

use js_sys::Promise;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::future_to_promise;
use web_sys::{Request, RequestInit, Response};

/// CreateWalletRequest
/// #Elements
/// email: user email
/// password: user password
/// threshold: FROST threshold x out of y (total)
/// total: FROST total share
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateWalletRequest {
    pub email: String,
    pub password: String,
    pub threshold: u16,
    pub total: u16,
}

/// CreateWalletResponse
/// client_shares: FROST client share
/// public_key_package: public key package
#[derive(Serialize)]
pub struct CreateWalletResponse {
    pub user_id: String,
    pub client_shares: Vec<(u16, Vec<u8>)>,
    pub public_key_package: Vec<u8>,
}

#[wasm_bindgen]
extern "C" {
    // Allow `console.log`from Rust`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// Calls the server POST /wallet/create endpoint and returns a Promise resolving to RegisterResult.
/// # Arguments
/// * api_base - Base URL of the API (e.g. "https://api.uniwallet.com")
/// * params - A JsValue representing `CreateWalletRequest`
#[wasm_bindgen]
pub fn create_wallet(api_base: String, params: JsValue) -> Promise {
    let params: CreateWalletRequest = from_value(params).unwrap();

    // Build the URL
    let url = format!("{}/wallet/create", api_base);

    // Spawn the async fetch to a JS Promise
    future_to_promise(async move {
        log(&format!("Calling register at {} with {:?}", url, params));
        // prepare the fetch options
        let opts = RequestInit::new();
        opts.set_method("POST");

        let body_str = serde_json::to_string(&params).unwrap();
        let js_str = JsValue::from_str(&body_str);
        opts.set_body(&js_str);

        let request = Request::new_with_str_and_init(&url, &opts).unwrap();
        request
            .headers()
            .set("Content-Type", "application/json")
            .unwrap();

        log(&format!("Request: {:?}", request));

        let resp_value = wasm_bindgen_futures::JsFuture::from(
            web_sys::window().unwrap().fetch_with_request(&request),
        )
        .await
        .map_err(|e| JsValue::from(format!("Fetch error: {:?}", e)))?;

        let response: Response = resp_value.dyn_into().unwrap();
        if !response.ok() {
            return Err(JsValue::from(format!("HTTP error {}", response.status())));
        }

        // Parse JSON
        let json = wasm_bindgen_futures::JsFuture::from(response.json().unwrap())
            .await
            .map_err(|e| JsValue::from(format!("JSON parse error {:?}", e)))?;

        Ok(json)
    })
}
