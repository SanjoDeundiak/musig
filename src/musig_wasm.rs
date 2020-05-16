use crate::musig::{MusigSession, MusigError};
use crate::musig_hash::Sha256HStar;
use franklin_crypto::alt_babyjubjub::{FixedGenerators, AltJubjubBn256};
use franklin_crypto::alt_babyjubjub::edwards::Point;
use franklin_crypto::alt_babyjubjub::Unknown;
use franklin_crypto::alt_babyjubjub::fs::{Fs, FsRepr};
use bellman::pairing::bn256::Bn256;
use bellman::pairing::ff::{PrimeFieldRepr, PrimeField};
use rand::thread_rng;
use wasm_bindgen::prelude::*;
use franklin_crypto::eddsa::{PublicKey, PrivateKey, Signature};

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
pub struct MusigVerifier {
}

#[wasm_bindgen]
impl MusigVerifier {
    #[wasm_bindgen]
    pub fn verify(msg: &[u8], aggregated_public_key: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
        let generator = FixedGenerators::SpendingKeyGenerator;

        let public_key = MusigWasm::read_public_key(aggregated_public_key)?;

        // FIXME: 65 hardcoded
        let r = MusigWasm::read_point(&signature[..65])?;
        let s = MusigWasm::read_fs(&signature[65..])?;

        let sig = Signature::<Bn256> {
            r,
            s
        };

        JUBJUB_PARAMS.with(|params| {
            Ok(public_key.verify_musig_sha256(msg, &sig, generator, params))
        })
    }
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

        let key = MusigWasm::read_public_key(participant_public_key)?;

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

        let session = MusigSession::<Bn256>::new(
            rng,
            Box::new(Sha256HStar {}),
            Box::new(Sha256HStar {}),
            Box::new(Sha256HStar {}),
            generator,
            // TODO: Reuse params?
            AltJubjubBn256::new(),
            self.participants,
            self.self_index
        ).map_err(MusigWasm::map_error_to_js)?;

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

    fn read_fs<R: std::io::Read>(reader: R) -> Result<Fs, JsValue> {
        let mut fs_repr = FsRepr::default();

        fs_repr.read_be(reader).map_err(MusigWasm::map_error_to_js)?;

        Fs::from_repr(fs_repr).map_err(MusigWasm::map_error_to_js)
    }

    fn read_private_key<R: std::io::Read>(reader: R) -> Result<PrivateKey<Bn256>, JsValue> {
        let fs = MusigWasm::read_fs(reader)?;

        Ok(PrivateKey::<Bn256>(fs))
    }

    fn read_point<R: std::io::Read>(reader: R) -> Result<Point<Bn256, Unknown>, JsValue> {
        // FIXME: Should it be thread-safe?
        JUBJUB_PARAMS.with(|params| {
            Point::<Bn256, Unknown>::read(reader, params)
        }).map_err(MusigWasm::map_error_to_js)
    }

    fn read_public_key<R: std::io::Read>(reader: R) -> Result<PublicKey<Bn256>, JsValue> {
        let point = MusigWasm::read_point(reader)?;

        Ok(PublicKey::<Bn256>(point))
    }

    fn write_public_key_w<W: std::io::Write>(public_key: &PublicKey<Bn256>, writer: W) -> Result<(), JsValue> {
        MusigWasm::write_point_w(&public_key.0, writer)
    }

    fn write_public_key(public_key: &PublicKey<Bn256>) -> Result<Vec<u8>, JsValue> {
        let mut vec: Vec<u8> = Vec::new();
        let res = MusigWasm::write_public_key_w(public_key, &mut vec);

        res.map(|_| {
            vec
        })
    }

    fn write_point_w<W: std::io::Write>(point: &Point<Bn256, Unknown>, writer: W) -> Result<(), JsValue> {
        point.write(writer).map_err(MusigWasm::map_error_to_js)
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
        let key = MusigWasm::read_public_key(r_pub)?;

        self.musig.set_r_pub(key, index).map_err(MusigWasm::map_musig_error_to_js)
    }

    #[wasm_bindgen]
    pub fn sign(&mut self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key = MusigWasm::read_private_key(sk)?;

        let res = self.musig
            .sign(&key, msg)
            .map_err(MusigWasm::map_musig_error_to_js)?;

        let mut vec: Vec::<u8> = Vec::new();

        res
            .into_repr()
            .write_le(&mut vec)
            .map(|_| {
                vec
            })
            .map_err(MusigWasm::map_error_to_js)
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
        fs.read_le(signature)
            .map_err(MusigWasm::map_error_to_js)
    }

    #[wasm_bindgen]
    pub fn get_signature(&self) -> Result<Vec<u8>, JsValue> {
        let signature = self.musig
            .aggregate_signature(&self.signatures)
            .map_err(MusigWasm::map_musig_error_to_js)?;

        let mut vec = Vec::new();

        signature.r
            .write(&mut vec)
            .map_err(MusigWasm::map_error_to_js)?;

        signature.s
            .into_repr()
            .write_le(&mut vec)
            .map_err(MusigWasm::map_error_to_js)?;

        Ok(vec)
    }
}