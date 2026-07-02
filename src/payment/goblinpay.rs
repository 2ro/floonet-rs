//! GoblinPay payment processor (Floonet addition).
//!
//! Talks to a GoblinPay server (the Grin payment backend) over its REST
//! API, using the same `PaymentProcessor` trait the Lightning processors
//! implement:
//!
//! * `POST /invoice`  (Bearer `GP_API_TOKEN`) creates an invoice; the
//!   response carries a hosted `pay_url` the payer opens to complete a
//!   Grin payment (GoblinPay, manual slatepack, or a `grin1` address if
//!   the operator enabled that method).
//! * `GET /invoice/{id}` returns the invoice's current status
//!   (`open` / `paid` / `expired`); GoblinPay marks it paid only after
//!   the payment confirms on chain (payment proof held server-side).
//!
//! Mapping onto the relay's invoice model: `payment_hash` holds the
//! GoblinPay `invoice_id`, and the `invoice` column (named `bolt11` in
//! code, an upstream Lightning artifact) holds the hosted `pay_url`.
//! Amounts are nanogrin (1 GRIN = 1_000_000_000 nanogrin).
//!
//! A GoblinPay webhook may POST `{"invoice_id": ...}` to this relay's
//! `/goblinpay` endpoint to speed up admission; the relay always
//! re-verifies with the GoblinPay server before admitting, so a forged
//! webhook cannot fake a payment (fail closed).

use http::Uri;
use hyper::client::connect::HttpConnector;
use hyper::Client;
use hyper_rustls::HttpsConnector;
use nostr::Keys;
use serde::{Deserialize, Serialize};

use async_trait::async_trait;
use std::str::FromStr;

use crate::error::Error;

use super::{InvoiceInfo, InvoiceStatus, PaymentProcessor};

/// JSON body for `POST /invoice`.
#[derive(Serialize, Debug)]
struct CreateInvoiceBody {
    /// Amount in nanogrin.
    amount_grin: u64,
    /// The relay's reference for this invoice.
    order_ref: String,
    memo: String,
}

/// The slice of GoblinPay's invoice JSON the relay needs.
#[derive(Deserialize, Debug)]
struct InvoiceResponse {
    invoice_id: String,
    pay_url: String,
    status: String,
}

#[derive(Clone)]
pub struct GoblinPayPaymentProcessor {
    client: hyper::Client<HttpsConnector<HttpConnector>, hyper::Body>,
    /// GoblinPay server base URL, no trailing slash.
    base_url: String,
    /// Bearer token (`GP_API_TOKEN`).
    api_token: String,
}

impl GoblinPayPaymentProcessor {
    pub fn new(base_url: &str, api_token: &str) -> Self {
        // https in production; plain http is accepted so a local GoblinPay
        // instance can be tested without certificates.
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder().build::<_, hyper::Body>(https);
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token: api_token.to_string(),
        }
    }

    fn status_from(&self, status: &str) -> InvoiceStatus {
        match status {
            "paid" => InvoiceStatus::Paid,
            "open" => InvoiceStatus::Unpaid,
            // Unknown statuses are treated as expired: fail closed.
            _ => InvoiceStatus::Expired,
        }
    }
}

#[async_trait]
impl PaymentProcessor for GoblinPayPaymentProcessor {
    /// Create a GoblinPay invoice for `amount` nanogrin.
    async fn get_invoice(&self, key: &Keys, amount: u64) -> Result<InvoiceInfo, Error> {
        let pubkey = key.public_key().to_string();
        let memo = format!("floonet relay: {pubkey}");
        let body = CreateInvoiceBody {
            amount_grin: amount,
            order_ref: format!("floonet:{pubkey}"),
            memo: memo.clone(),
        };
        let uri = Uri::from_str(&format!("{}/invoice", self.base_url))
            .map_err(|_| Error::CustomError("invalid goblinpay url".to_string()))?;
        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(uri)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .body(hyper::Body::from(serde_json::to_string(&body)?))
            .expect("request builder");

        let res = self.client.request(req).await?;
        if !res.status().is_success() {
            return Err(Error::CustomError(format!(
                "goblinpay create invoice failed: HTTP {}",
                res.status()
            )));
        }
        let body = hyper::body::to_bytes(res.into_body()).await?;
        let invoice: InvoiceResponse = serde_json::from_slice(&body)?;

        Ok(InvoiceInfo {
            pubkey,
            payment_hash: invoice.invoice_id,
            bolt11: invoice.pay_url,
            amount,
            memo,
            status: self.status_from(&invoice.status),
            confirmed_at: None,
        })
    }

    /// Ask GoblinPay for the invoice's current status. GoblinPay only
    /// reports `paid` after the Grin payment confirmed on chain.
    async fn check_invoice(&self, payment_hash: &str) -> Result<InvoiceStatus, Error> {
        // The id is server-generated, but never let a crafted value alter
        // the request path.
        if !payment_hash
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::CustomError("invalid invoice id".to_string()));
        }
        let uri = Uri::from_str(&format!("{}/invoice/{}", self.base_url, payment_hash))
            .map_err(|_| Error::CustomError("invalid goblinpay url".to_string()))?;
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .body(hyper::Body::empty())
            .expect("request builder");

        let res = self.client.request(req).await?;
        if !res.status().is_success() {
            return Err(Error::CustomError(format!(
                "goblinpay check invoice failed: HTTP {}",
                res.status()
            )));
        }
        let body = hyper::body::to_bytes(res.into_body()).await?;
        let invoice: InvoiceResponse = serde_json::from_slice(&body)?;
        Ok(self.status_from(&invoice.status))
    }
}
