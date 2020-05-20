use crate::musig::{MusigError, MusigSession, MusigVerifier};
use crate::musig_hash::Sha256HStar;
use bellman::pairing::bn256::Bn256;
use bellman::pairing::ff::{PrimeField, PrimeFieldRepr};
use franklin_crypto::alt_babyjubjub::edwards::Point;
use franklin_crypto::alt_babyjubjub::fs::{Fs, FsRepr};
use franklin_crypto::alt_babyjubjub::Unknown;
use franklin_crypto::alt_babyjubjub::{AltJubjubBn256, FixedGenerators};
use franklin_crypto::eddsa::{PrivateKey, PublicKey, Seed, Signature};
use rand::{Rng, SeedableRng, StdRng};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

pub const PACKED_POINT_SIZE: usize = 32;
pub const FS_SIZE: usize = 32;

lazy_static! {
    static ref JUBJUB_PARAMS: AltJubjubBn256 = AltJubjubBn256::new();
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
pub struct MusigWasmVerifier {
    verifier: MusigVerifier,
}

#[wasm_bindgen]
impl MusigWasmVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(hash: MusigHash) -> MusigWasmVerifier {
        let generator = FixedGenerators::SpendingKeyGenerator;

        let msg_hash = match hash {
            MusigHash::SHA256 => Box::new(Sha256HStar {}),
        };

        let verifier = MusigVerifier::new(msg_hash, generator);

        MusigWasmVerifier { verifier }
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

        let public_key = MusigWasmFormats::read_public_key(aggregated_public_key)?;

        let (aggregated_public_key_embedded, sig) = signature.split_at(PACKED_POINT_SIZE);

        if aggregated_public_key_embedded != aggregated_public_key {
            return Err(JsValue::from("Aggregated public key doesn't match"));
        }

        let (r, s) = sig.split_at(PACKED_POINT_SIZE);

        let r = MusigWasmFormats::read_point(r)?;
        let s = MusigWasmFormats::read_fs_le(s)?;

        let sig = Signature::<Bn256> { r, s };

        Ok(self
            .verifier
            .verify_signature(&sig, msg, &public_key, &JUBJUB_PARAMS))
    }
}

struct MusigWasmFormats {}

/// Fs
impl MusigWasmFormats {
    fn read_fs(reader: &[u8], be: bool) -> Result<Fs, JsValue> {
        let mut fs_repr = FsRepr::default();

        let res = if be {
            fs_repr.read_be(reader)
        } else {
            fs_repr.read_le(reader)
        };

        res.map_err(MusigWasmFormats::map_error_to_js)?;

        Fs::from_repr(fs_repr).map_err(MusigWasmFormats::map_error_to_js)
    }

    fn read_fs_be(reader: &[u8]) -> Result<Fs, JsValue> {
        MusigWasmFormats::read_fs(reader, true)
    }

    fn read_fs_le(reader: &[u8]) -> Result<Fs, JsValue> {
        MusigWasmFormats::read_fs(reader, false)
    }

    fn write_fs<W: std::io::Write>(fs: &Fs, be: bool, writer: W) -> Result<(), JsValue> {
        let repr = fs.into_repr();

        let res = if be {
            repr.write_be(writer)
        } else {
            repr.write_le(writer)
        };

        res.map_err(MusigWasmFormats::map_error_to_js)
    }

    fn write_fs_be<W: std::io::Write>(fs: &Fs, writer: W) -> Result<(), JsValue> {
        MusigWasmFormats::write_fs(fs, true, writer)
    }

    fn write_fs_le<W: std::io::Write>(fs: &Fs, writer: W) -> Result<(), JsValue> {
        MusigWasmFormats::write_fs(fs, false, writer)
    }
}

/// Private keys
impl MusigWasmFormats {
    fn read_private_key(reader: &[u8]) -> Result<PrivateKey<Bn256>, JsValue> {
        let fs = MusigWasmFormats::read_fs_be(reader)?;

        Ok(PrivateKey::<Bn256>(fs))
    }

    fn write_private_key<W: std::io::Write>(
        private_key: &PrivateKey<Bn256>,
        writer: W,
    ) -> Result<(), JsValue> {
        MusigWasmFormats::write_fs_be(&private_key.0, writer)
    }
}

/// Public keys
impl MusigWasmFormats {
    fn read_public_key(reader: &[u8]) -> Result<PublicKey<Bn256>, JsValue> {
        let point = MusigWasmFormats::read_point(reader)?;

        Ok(PublicKey::<Bn256>(point))
    }

    fn write_public_key<W: std::io::Write>(
        public_key: &PublicKey<Bn256>,
        writer: W,
    ) -> Result<(), JsValue> {
        MusigWasmFormats::write_point(&public_key.0, writer)
    }
}

/// Points
impl MusigWasmFormats {
    fn read_point(reader: &[u8]) -> Result<Point<Bn256, Unknown>, JsValue> {
        let p = Point::<Bn256, Unknown>::read(reader, &JUBJUB_PARAMS)
            .map_err(MusigWasmFormats::map_error_to_js)?;

        // this one is for a simple sanity check. In application purposes the pk will always be in a right group
        let order_check_pk = p.mul(Fs::char(), &JUBJUB_PARAMS);
        if !order_check_pk.eq(&Point::zero()) {
            return Err(JsValue::from("Invalid point"));
        }

        Ok(p)
    }

    fn write_point<W: std::io::Write>(
        point: &Point<Bn256, Unknown>,
        writer: W,
    ) -> Result<(), JsValue> {
        point
            .write(writer)
            .map_err(MusigWasmFormats::map_error_to_js)
    }
}

/// Errors
impl MusigWasmFormats {
    fn map_error_to_js(err: impl std::error::Error) -> JsValue {
        JsValue::from(err.to_string())
    }

    fn map_musig_error_to_js(err: MusigError) -> JsValue {
        JsValue::from(err.description())
    }
}

#[wasm_bindgen]
pub struct MusigWasmUtils {}

#[wasm_bindgen]
impl MusigWasmUtils {
    #[wasm_bindgen(js_name = "generatePrivateKey")]
    pub fn generate_private_key(seed: &[usize]) -> Result<Vec<u8>, JsValue> {
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let private_key = PrivateKey::<Bn256>(rng.gen());

        let mut vec = Vec::<u8>::new();

        MusigWasmFormats::write_private_key(&private_key, &mut vec)?;

        Ok(vec)
    }

    #[wasm_bindgen(js_name = "extractPublicKey")]
    pub fn extract_public_key(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
        let private_key = MusigWasmFormats::read_private_key(private_key)?;

        let public_key = PublicKey::<Bn256>::from_private(
            &private_key,
            FixedGenerators::SpendingKeyGenerator,
            &JUBJUB_PARAMS,
        );

        let mut vec = Vec::<u8>::new();

        MusigWasmFormats::write_public_key(&public_key, &mut vec)?;

        Ok(vec)
    }
}

#[wasm_bindgen]
pub enum MusigHash {
    SHA256,
}

#[wasm_bindgen]
pub struct MusigWasmBuilder {
    participants: Vec<PublicKey<Bn256>>,
    seed: Option<Seed<Bn256>>,
    self_index: usize,
    set_self_index: bool,
    hash: MusigHash,
}

#[wasm_bindgen]
impl MusigWasmBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> MusigWasmBuilder {
        MusigWasmBuilder {
            participants: Vec::new(),
            seed: None,
            self_index: 0,
            set_self_index: false,
            hash: MusigHash::SHA256,
        }
    }

    #[wasm_bindgen(js_name = "setAllHashes")]
    pub fn set_all_hashes(&mut self, hash: MusigHash) {
        self.hash = hash;
    }

    #[wasm_bindgen(js_name = "deriveSeed")]
    pub fn derive_seed(&mut self, sk: &[u8], msg: &[u8]) -> Result<(), JsValue> {
        let sk = MusigWasmFormats::read_private_key(sk)?;

        let hashed_msg = match self.hash {
            MusigHash::SHA256 => {
                let mut sha256 = Sha256::default();

                sha256.input(msg);

                sha256.result().to_vec()
            }
        };

        self.seed = Some(Seed::deterministic_seed(&sk, &hashed_msg));

        Ok(())
    }

    #[wasm_bindgen(js_name = "addParticipant")]
    pub fn add_participant(
        &mut self,
        participant_public_key: &[u8],
        is_me: bool,
    ) -> Result<(), JsValue> {
        if is_me && self.set_self_index {
            return Err(JsValue::from("Second self key"));
        }

        let key = MusigWasmFormats::read_public_key(participant_public_key)?;

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
            return Err(JsValue::from("No self index"));
        }

        let seed = self.seed.ok_or_else(|| JsValue::from("No seed"))?;

        let generator = FixedGenerators::SpendingKeyGenerator;

        let aggregate_hash = match self.hash {
            MusigHash::SHA256 => Box::new(Sha256HStar {}),
        };

        let commitment_hash = match self.hash {
            MusigHash::SHA256 => Box::new(Sha256HStar {}),
        };

        let signature_hash = match self.hash {
            MusigHash::SHA256 => Box::new(Sha256HStar {}),
        };

        let msg_hash = match self.hash {
            MusigHash::SHA256 => Box::new(Sha256HStar {}),
        };

        let session = MusigSession::<Bn256>::new(
            aggregate_hash,
            commitment_hash,
            signature_hash,
            msg_hash,
            generator,
            &JUBJUB_PARAMS,
            self.participants,
            seed,
            self.self_index,
        )
        .map_err(MusigWasmFormats::map_error_to_js)?;

        let musig = MusigWasm { musig: session };

        Ok(musig)
    }
}

impl Default for MusigWasmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct MusigWasm {
    musig: MusigSession<Bn256>,
}

#[wasm_bindgen]
impl MusigWasm {
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

        MusigWasmFormats::write_public_key(self.musig.get_r_pub(), &mut vec)?;

        Ok(vec)
    }

    #[wasm_bindgen(js_name = "getAggregatedPublicKey")]
    pub fn get_aggregated_public_key(&self) -> Result<Vec<u8>, JsValue> {
        let mut vec = Vec::<u8>::new();

        MusigWasmFormats::write_public_key(self.musig.get_aggregated_public_key(), &mut vec)?;

        Ok(vec)
    }

    #[wasm_bindgen(js_name = "setT")]
    pub fn set_t(&mut self, t: &[u8], index: usize) -> Result<(), JsValue> {
        self.musig
            .set_t(t, index)
            .map_err(MusigWasmFormats::map_musig_error_to_js)
    }

    #[wasm_bindgen(js_name = "setRPub")]
    pub fn set_r_pub(&mut self, r_pub: &[u8], index: usize) -> Result<(), JsValue> {
        let key = MusigWasmFormats::read_public_key(r_pub)?;

        self.musig
            .set_r_pub(key, index, &JUBJUB_PARAMS)
            .map_err(MusigWasmFormats::map_musig_error_to_js)
    }

    #[wasm_bindgen]
    pub fn sign(&mut self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key = MusigWasmFormats::read_private_key(sk)?;

        let res = self
            .musig
            .sign(&key, msg)
            .map_err(MusigWasmFormats::map_musig_error_to_js)?;

        let mut vec: Vec<u8> = Vec::new();

        MusigWasmFormats::write_fs_le(&res, &mut vec).map(|_| vec)
    }

    #[wasm_bindgen(js_name = "buildSignatureAggregator")]
    pub fn build_signature_aggregator(self) -> MusigWasmSignatureAggregator {
        let aggregated_public_key = self.musig.get_aggregated_public_key().clone();

        MusigWasmSignatureAggregator {
            musig: self.musig,
            signatures: Vec::new(),
            aggregated_public_key,
        }
    }
}

#[wasm_bindgen]
pub struct MusigWasmSignatureAggregator {
    musig: MusigSession<Bn256>,
    signatures: Vec<Fs>,
    aggregated_public_key: PublicKey<Bn256>,
}

#[wasm_bindgen]
impl MusigWasmSignatureAggregator {
    #[wasm_bindgen(js_name = "addSignature")]
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), JsValue> {
        let s = MusigWasmFormats::read_fs_le(signature)?;

        self.signatures.push(s);

        Ok(())
    }

    #[wasm_bindgen(js_name = "getSignature")]
    pub fn get_signature(&self) -> Result<Vec<u8>, JsValue> {
        let signature = self
            .musig
            .aggregate_signature(&self.signatures)
            .map_err(MusigWasmFormats::map_musig_error_to_js)?;

        let mut vec = Vec::new();

        MusigWasmFormats::write_public_key(&self.aggregated_public_key, &mut vec)?;
        MusigWasmFormats::write_point(&signature.r, &mut vec)?;
        MusigWasmFormats::write_fs_le(&signature.s, &mut vec)?;

        Ok(vec)
    }
}

#[cfg(test)]
mod musig_wasm_unit_tests {
    use crate::musig_wasm::{MusigWasmFormats, MusigWasmUtils};

    #[test]
    fn read_write() {
        let seed = [1usize; 8];

        let sk_data = MusigWasmUtils::generate_private_key(&seed).expect("");

        let sk = MusigWasmFormats::read_private_key(&sk_data[..]).expect("");

        let mut sk_data2 = Vec::<u8>::new();

        MusigWasmFormats::write_private_key(&sk, &mut sk_data2).expect("");

        assert_eq!(sk_data, sk_data2);

        let pk_data = MusigWasmUtils::extract_public_key(&sk_data).expect("");

        let pk = MusigWasmFormats::read_public_key(&pk_data[..]).expect("");

        let mut pk_data2 = Vec::<u8>::new();

        MusigWasmFormats::write_public_key(&pk, &mut pk_data2).expect("");

        assert_eq!(pk_data, pk_data2);
    }
}
