use crate::musig::{MusigSession, MusigError};
use crate::musig_hash::Sha256HStar;
use franklin_crypto::alt_babyjubjub::{FixedGenerators, AltJubjubBn256};
use franklin_crypto::alt_babyjubjub::fs::{Fs, FsRepr};
use bellman::pairing::bn256::Bn256;
use bellman::pairing::ff::{PrimeFieldRepr, PrimeField};
use rand::thread_rng;
use wasm_bindgen::prelude::*;
use franklin_crypto::eddsa::{PublicKey, PrivateKey};

// FIXME: Why would we need that?
thread_local! {
    pub static JUBJUB_PARAMS: AltJubjubBn256 = AltJubjubBn256::new();
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
    JUBJUB_PARAMS.with(|_| {});
    set_panic_hook();
}

#[wasm_bindgen]
pub struct MusigWasmBuilder {
    participants: Vec<PublicKey<Bn256>>,
    self_index: usize,
    set_self_index: bool,
}

#[wasm_bindgen]
impl MusigWasmBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> MusigWasmBuilder {
        MusigWasmBuilder {
            participants: Vec::new(),
            self_index: 0,
            set_self_index: false,
        }
    }

    #[wasm_bindgen]
    pub fn add_participant(&mut self, participant_public_key: &[u8], is_me: bool) -> Result<(), JsValue> {
        if is_me && self.set_self_index {
            return Err(JsValue::from("Second self key"))
        }

        let key = match MusigWasm::read_public_key(participant_public_key) {
            Ok(key) => key,
            Err(err) => return Err(err)
        };

        if is_me {
            self.self_index = self.participants.len();
            self.set_self_index = true;
        }

        self.participants.push(key);

        Ok(())
    }

    #[wasm_bindgen]
    pub fn build(self) -> Result<MusigWasm, JsValue> {
        if !self.set_self_index {
            return Err(JsValue::from("No self index"))
        }

        // FIXME
        let rng = &mut thread_rng();
        let generator = FixedGenerators::SpendingKeyGenerator;

        let session = match MusigSession::<Bn256>::new(
            rng,
            Box::new(Sha256HStar {}),
            Box::new(Sha256HStar {}),
            Box::new(Sha256HStar {}),
            generator,
            // TODO: Reuse params?
            AltJubjubBn256::new(),
            self.participants,
            self.self_index
        ) {
            Ok(session) => session,
            Err(err) => return Err(JsValue::from(err.description()))
        };

        let musig = MusigWasm {
            musig: session
        };

        Ok(musig)
    }
}

#[wasm_bindgen]
pub struct MusigWasm {
    musig: MusigSession<Bn256>,
}

#[wasm_bindgen]
impl MusigWasm {
    fn map_error_to_js(err: impl std::error::Error) -> JsValue {
        JsValue::from(err.to_string())
    }

    fn map_musig_error_to_js(err: MusigError) -> JsValue {
        JsValue::from(err.description())
    }

    fn read_private_key(private_key: &[u8]) -> Result<PrivateKey<Bn256>, JsValue> {
        let mut fs_repr = FsRepr::default();

        match fs_repr.read_be(private_key) {
            Ok(_) => {},
            Err(err) => return Err(JsValue::from(err.to_string())),
        }

        let fs = match Fs::from_repr(fs_repr) {
            Ok(fs) => fs,
            Err(err) => return Err(JsValue::from(err.to_string())),
        };

        Ok(PrivateKey::<Bn256>(fs))
    }

    fn read_public_key(public_key: &[u8]) -> Result<PublicKey<Bn256>, JsValue> {
        // FIXME: Should it be thread-safe?
        match JUBJUB_PARAMS.with(|params| {
            PublicKey::<Bn256>::read(public_key, params)
        }) {
            Ok(key) => Ok(key),
            Err(err) => return Err(JsValue::from(err.to_string())),
        }
    }

    fn write_public_key_w<W: std::io::Write>(public_key: &PublicKey<Bn256>, writer: W) -> Result<(), JsValue> {
        public_key.write(writer).map_err(MusigWasm::map_error_to_js)
    }

    fn write_public_key(public_key: &PublicKey<Bn256>) -> Result<Vec<u8>, JsValue> {
        let mut vec: Vec<u8> = Vec::new();
        let res = MusigWasm::write_public_key_w(public_key, &mut vec);

        match res {
            Ok(_) => Ok(vec),
            Err(err) => return Err(err)
        }
    }

    #[wasm_bindgen]
    pub fn get_self_index(&self) -> usize {
        self.musig.get_self_index()
    }

    #[wasm_bindgen]
    pub fn get_t(&self) -> Vec<u8> {
        self.musig.get_t().clone()
    }

    #[wasm_bindgen]
    pub fn get_r_pub(&self) -> Result<Vec<u8>, JsValue> {
        MusigWasm::write_public_key(self.musig.get_r_pub())
    }

    #[wasm_bindgen]
    pub fn get_aggregated_public_key(&self) -> Result<Vec<u8>, JsValue> {
        MusigWasm::write_public_key(self.musig.get_aggregated_public_key())
    }

    #[wasm_bindgen]
    pub fn set_t(&mut self, t: &[u8], index: usize) -> Result<(), JsValue> {
        self.musig.set_t(t, index).map_err(MusigWasm::map_musig_error_to_js)
    }

    #[wasm_bindgen]
    pub fn set_r_pub(&mut self, r_pub: &[u8], index: usize) -> Result<(), JsValue> {
        let key = match MusigWasm::read_public_key(&r_pub) {
            Ok(key) => key,
            Err(err) => return Err(err)
        };

        self.musig.set_r_pub(key, index).map_err(MusigWasm::map_musig_error_to_js)
    }

    #[wasm_bindgen]
    pub fn sign(&mut self, sk: &[u8], m: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key = match MusigWasm::read_private_key(&sk) {
            Ok(key) => key,
            Err(err) => return Err(err)
        };

        let res = self.musig
            .sign(&key, m)
            .map_err(MusigWasm::map_musig_error_to_js);

        let res = match res {
            Ok(s) => s,
            Err(err) => return Err(err),
        };

        let mut vec: Vec::<u8> = Vec::new();

        match res
            .into_repr()
            .write_le(&mut vec) {
            Ok(_) => Ok(vec),
            Err(err) => Err(err),
        }.map_err(MusigWasm::map_error_to_js)
    }

    #[wasm_bindgen]
    pub fn build_signature_aggregator(self) -> MusigWasmSignatureAggregator {
        MusigWasmSignatureAggregator {
            musig: self.musig,
            signatures: Vec::new(),
        }
    }
}

#[wasm_bindgen]
pub struct MusigWasmSignatureAggregator {
    musig: MusigSession<Bn256>,
    signatures: Vec::<Fs>,
}

#[wasm_bindgen]
impl MusigWasmSignatureAggregator {
    #[wasm_bindgen]
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), JsValue> {
        let mut fs = FsRepr::default();
        match fs.read_le(signature) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }.map_err(MusigWasm::map_error_to_js)
    }

    #[wasm_bindgen]
    pub fn get_signature(&self) -> Result<Vec<u8>, JsValue> {
        let signature = match self.musig
            .aggregate_signature(&self.signatures)
            .map_err(MusigWasm::map_musig_error_to_js) {
            Ok(s) => s,
            Err(err) => return Err(err),
        };

        let mut vec = Vec::new();

        match signature.r
            .write(&mut vec)
            .map_err(MusigWasm::map_error_to_js) {
            Ok(_) => {},
            Err(err) => return Err(err),
        }

        match signature.s
            .into_repr()
            .write_le(&mut vec)
            .map_err(MusigWasm::map_error_to_js) {
            Ok(_) => {},
            Err(err) => return Err(err),
        }

        Ok(vec)
    }
}