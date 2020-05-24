use bellman::pairing::bn256::Bn256;
use franklin_crypto::alt_babyjubjub::FixedGenerators;
use franklin_crypto::eddsa::{PrivateKey, PublicKey};
use rand::{Rng, SeedableRng, StdRng};
use wasm_bindgen::prelude::*;

use crate::wasm_formats::WasmFormats;
use crate::musig_wasm::JUBJUB_PARAMS;

#[wasm_bindgen(js_name = "MusigWasmUtils")]
pub struct Utils {}

#[wasm_bindgen(js_class = "MusigWasmUtils")]
impl Utils {
    #[wasm_bindgen(js_name = "generatePrivateKey")]
    pub fn generate_private_key(seed: &[usize]) -> Result<Vec<u8>, JsValue> {
        let mut rng = StdRng::from_seed(seed);

        let private_key = PrivateKey::<Bn256>(rng.gen());

        let mut vec = Vec::<u8>::new();

        WasmFormats::write_private_key(&private_key, &mut vec)?;

        Ok(vec)
    }

    #[wasm_bindgen(js_name = "extractPublicKey")]
    pub fn extract_public_key(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
        let private_key = WasmFormats::read_private_key(private_key)?;

        let public_key = PublicKey::<Bn256>::from_private(
            &private_key,
            FixedGenerators::SpendingKeyGenerator,
            &JUBJUB_PARAMS,
        );

        let mut vec = Vec::<u8>::new();

        WasmFormats::write_public_key(&public_key, &mut vec)?;

        Ok(vec)
    }
}