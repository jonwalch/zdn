//! Finite method-specific transport classes. This never grants RPC authority.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_BODY: usize = 8 * 1024 * 1024;
pub const LARGE_HEX_BODY: usize = 40_100_000;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BodyClass {
    #[default]
    Default,
    LargeHexV1,
}
impl BodyClass {
    pub fn ceiling(self) -> usize {
        if self == Self::LargeHexV1 {
            LARGE_HEX_BODY
        } else {
            DEFAULT_BODY
        }
    }
    pub fn request(self, method: &str) -> usize {
        if self == Self::LargeHexV1
            && matches!(
                method,
                "sendrawtransaction" | "submitblock" | "inspectchainblock"
            )
        {
            LARGE_HEX_BODY
        } else {
            DEFAULT_BODY
        }
    }
    pub fn response(self, method: &str, params: &Value) -> usize {
        // Only encoded hex, not unbounded decoded/verbose block objects. An
        // omitted verbosity defaults to verbose on getblock, so stays small.
        let raw = params.as_array().is_some_and(|p| {
            matches!(p.as_slice(), [Value::String(_), verbosity]
                if verbosity.as_u64() == Some(0) || verbosity.as_bool() == Some(false))
        });
        let raw_transaction = method == "getrawtransaction"
            && (raw
                || params
                    .as_array()
                    .is_some_and(|p| matches!(p.as_slice(), [Value::String(_)])));
        if self == Self::LargeHexV1 && ((method == "getblock" && raw) || raw_transaction) {
            LARGE_HEX_BODY
        } else {
            DEFAULT_BODY
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn finite_classes_do_not_enlarge_metadata_or_verbose_objects() {
        let large = BodyClass::LargeHexV1;
        assert_eq!(large.request("sendrawtransaction"), 40_100_000);
        assert_eq!(large.request("getchainrules"), DEFAULT_BODY);
        assert_eq!(large.response("getblock", &json!(["hash", 0])), 40_100_000);
        for p in [
            json!(["hash"]),
            json!(["hash", 1]),
            json!(["hash", 2]),
            json!(["hash", 0, "extra"]),
            json!(["hash", 0.0]),
            json!([null, 0]),
            json!({"verbosity":0}),
        ] {
            assert_eq!(large.response("getblock", &p), DEFAULT_BODY);
        }
        for p in [json!([null]), json!(["txid", 0, "extra"])] {
            assert_eq!(large.response("getrawtransaction", &p), DEFAULT_BODY);
        }
        assert_eq!(
            large.response("getrawtransaction", &json!(["txid"])),
            40_100_000
        );
        assert_eq!(
            large.response("getblockchaininfo", &json!([])),
            DEFAULT_BODY
        );
        assert_eq!(
            BodyClass::Default.response("getblock", &json!(["hash", 0])),
            DEFAULT_BODY
        );
        assert_eq!(
            BodyClass::Default.request("sendrawtransaction"),
            DEFAULT_BODY
        );
    }
}
