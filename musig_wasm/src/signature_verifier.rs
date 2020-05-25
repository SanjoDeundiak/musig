use bellman::pairing::bn256::Bn256;
use franklin_crypto::alt_babyjubjub::FixedGenerators;
use franklin_crypto::eddsa::Signature;
use musig::hash::{DefaultHasher, Sha256HStar, Sha512HStarAggregate};
use musig::musig::MusigVerifier;
use wasm_bindgen::prelude::*;

use crate::musig_wasm::{FS_SIZE, JUBJUB_PARAMS, PACKED_POINT_SIZE};
use crate::wasm_formats::WasmFormats;

#[wasm_bindgen(js_name = "MusigWasmVerifier")]
pub struct SignatureVerifier {
    verifier: MusigVerifier<Bn256, DefaultHasher<Bn256>>,
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        SignatureVerifier::new()
    }
}

#[wasm_bindgen(js_class = "MusigWasmVerifier")]
impl SignatureVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let generator = FixedGenerators::SpendingKeyGenerator;

        let hasher = DefaultHasher::new(
            Sha512HStarAggregate::new(),
            Sha256HStar::new(),
            Sha256HStar::new(),
            Sha256HStar::new(),
        );

        let verifier = MusigVerifier::new(hasher, generator);

        SignatureVerifier { verifier }
    }

    #[wasm_bindgen]
    pub fn verify(
        &self,
        msg: &[u8],
        aggregated_public_key: &[u8],
        signature: &[u8],
    ) -> Result<bool, JsValue> {
        if signature.len() != 2 * PACKED_POINT_SIZE + FS_SIZE {
            return Err(JsValue::from("Invalid signature size"));
        }

        let public_key = WasmFormats::read_public_key(aggregated_public_key, &JUBJUB_PARAMS)?;

        let (aggregated_public_key_embedded, sig) = signature.split_at(PACKED_POINT_SIZE);

        if aggregated_public_key_embedded != aggregated_public_key {
            return Err(JsValue::from("Aggregated public key doesn't match"));
        }

        let (r, s) = sig.split_at(PACKED_POINT_SIZE);

        let r = WasmFormats::read_point(r, &JUBJUB_PARAMS)?;
        let s = WasmFormats::read_fs_le(s)?;

        let sig = Signature::<Bn256> { r, s };

        Ok(self
            .verifier
            .verify_signature(&sig, msg, &public_key, &JUBJUB_PARAMS))
    }
}
