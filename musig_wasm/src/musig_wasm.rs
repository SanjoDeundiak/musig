use musig::musig::MusigSession;
use bellman::pairing::bn256::Bn256;
use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use wasm_bindgen::prelude::*;

use crate::wasm_formats::WasmFormats;
use crate::signature_aggregator::SignatureAggregator;

pub const PACKED_POINT_SIZE: usize = 32;
pub const FS_SIZE: usize = 32;

lazy_static! {
    pub static ref JUBJUB_PARAMS: AltJubjubBn256 = AltJubjubBn256::new();
}

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn init() {
    set_panic_hook();
    let _ = &JUBJUB_PARAMS;
}

#[wasm_bindgen]
pub struct MusigWasm {
    musig: MusigSession<Bn256>,
}

#[wasm_bindgen]
impl MusigWasm {
    pub(crate) fn new(musig: MusigSession<Bn256>) -> Self {
        MusigWasm {
            musig,
        }
    }

    #[wasm_bindgen(js_name = "getSelfIndex")]
    pub fn get_self_index(&self) -> usize {
        self.musig.get_self_index()
    }

    #[wasm_bindgen(js_name = "getT")]
    pub fn get_t(&self) -> Vec<u8> {
        self.musig.get_t().clone()
    }

    #[wasm_bindgen(js_name = "getRPub")]
    pub fn get_r_pub(&self) -> Result<Vec<u8>, JsValue> {
        let mut vec = Vec::<u8>::new();

        WasmFormats::write_public_key(self.musig.get_r_pub(), &mut vec)?;

        Ok(vec)
    }

    #[wasm_bindgen(js_name = "getAggregatedPublicKey")]
    pub fn get_aggregated_public_key(&self) -> Result<Vec<u8>, JsValue> {
        let mut vec = Vec::<u8>::new();

        WasmFormats::write_public_key(self.musig.get_aggregated_public_key(), &mut vec)?;

        Ok(vec)
    }

    #[wasm_bindgen(js_name = "setT")]
    pub fn set_t(&mut self, t: &[u8], index: usize) -> Result<(), JsValue> {
        self.musig
            .set_t(t, index)
            .map_err(WasmFormats::map_musig_error_to_js)
    }

    #[wasm_bindgen(js_name = "setRPub")]
    pub fn set_r_pub(&mut self, r_pub: &[u8], index: usize) -> Result<(), JsValue> {
        let key = WasmFormats::read_public_key(r_pub, &JUBJUB_PARAMS)?;

        self.musig
            .set_r_pub(key, index, &JUBJUB_PARAMS)
            .map_err(WasmFormats::map_musig_error_to_js)
    }

    #[wasm_bindgen]
    pub fn sign(&mut self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key = WasmFormats::read_private_key(sk)?;

        let res = self
            .musig
            .sign(&key, msg)
            .map_err(WasmFormats::map_musig_error_to_js)?;

        let mut vec: Vec<u8> = Vec::new();

        WasmFormats::write_fs_le(&res, &mut vec).map(|_| vec)
    }

    #[wasm_bindgen(js_name = "buildSignatureAggregator")]
    pub fn build_signature_aggregator(self) -> SignatureAggregator {
        let aggregated_public_key = self.musig.get_aggregated_public_key().clone();

        SignatureAggregator::new(self.musig, aggregated_public_key)
    }
}

#[cfg(test)]
mod musig_wasm_unit_tests {
    use crate::utils::Utils;
    use crate::wasm_formats::WasmFormats;
    use franklin_crypto::alt_babyjubjub::AltJubjubBn256;

    #[test]
    fn read_write() {
        let seed = [1usize; 8];
        let params = AltJubjubBn256::new();

        let sk_data = Utils::generate_private_key(&seed).expect("");

        let sk = WasmFormats::read_private_key(&sk_data[..]).expect("");

        let mut sk_data2 = Vec::<u8>::new();

        WasmFormats::write_private_key(&sk, &mut sk_data2).expect("");

        assert_eq!(sk_data, sk_data2);

        let pk_data = Utils::extract_public_key(&sk_data).expect("");

        let pk = WasmFormats::read_public_key(&pk_data[..], &params).expect("");

        let mut pk_data2 = Vec::<u8>::new();

        WasmFormats::write_public_key(&pk, &mut pk_data2).expect("");

        assert_eq!(pk_data, pk_data2);
    }
}
