use crate::musig::{MusigSession, MusigError, MusigVerifier};
use crate::musig_hash::Sha256HStar;
use franklin_crypto::alt_babyjubjub::{FixedGenerators, AltJubjubBn256};
use franklin_crypto::alt_babyjubjub::edwards::Point;
use franklin_crypto::alt_babyjubjub::Unknown;
use franklin_crypto::alt_babyjubjub::fs::{Fs, FsRepr};
use bellman::pairing::bn256::Bn256;
use bellman::pairing::ff::{PrimeFieldRepr, PrimeField};
use wasm_bindgen::prelude::*;
use franklin_crypto::eddsa::{PublicKey, PrivateKey, Signature, Seed};
use sha2::{Sha256, Digest};
use rand::{StdRng, SeedableRng, Rng};

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
pub struct MusigWasmVerifier {
    verifier: MusigVerifier<Bn256>
}

#[wasm_bindgen]
impl MusigWasmVerifier {
    #[wasm_bindgen]
    pub fn new() -> MusigWasmVerifier {
        let generator = FixedGenerators::SpendingKeyGenerator;

        // TODO: Set hash

        let msg_hash = Box::new(Sha256HStar {});

        let verifier = MusigVerifier::new(
            msg_hash,
            generator,
            AltJubjubBn256::new(),
        );

        MusigWasmVerifier {
            verifier
        }
    }

    #[wasm_bindgen]
    pub fn verify(&self, msg: &[u8], aggregated_public_key: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
        let public_key = MusigWasm::read_public_key(aggregated_public_key)?;

        // FIXME: 32 hardcoded
        let r = MusigWasm::read_point(&signature[..32])?;
        let s = MusigWasm::read_fs(&signature[32..])?;

        let sig = Signature::<Bn256> {
            r,
            s
        };

        Ok(self.verifier.verify_signature(&sig, msg, &public_key))
    }
}

#[wasm_bindgen]
pub struct MusigWasmUtils {

}

#[wasm_bindgen]
impl MusigWasmUtils {
    #[wasm_bindgen]
    pub fn generate_private_key(seed: &[usize]) -> Result<Vec<u8>, JsValue> {
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let private_key = PrivateKey::<Bn256>(rng.gen());

        MusigWasm::write_private_key(&private_key)
    }

    #[wasm_bindgen]
    pub fn extract_public_key(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
        let private_key = MusigWasm::read_private_key(private_key)?;

        let public_key = JUBJUB_PARAMS.with(|params| {
            PublicKey::<Bn256>::from_private(&private_key,
                                             FixedGenerators::SpendingKeyGenerator /* FIXME */,
                                             params
            )
        });

        MusigWasm::write_public_key(&public_key)
    }
}

#[wasm_bindgen]
pub enum MusigHash {
    SHA256
}

#[wasm_bindgen]
pub struct MusigWasmBuilder {
    participants: Vec<PublicKey<Bn256>>,
    seed: Option<Seed<Bn256>>,
    self_index: usize,
    set_self_index: bool,
    hash: MusigHash
}

// FIXME: Add (js_name = "")

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

    #[wasm_bindgen]
    pub fn set_all_hashes(&mut self, hash: MusigHash) {
        self.hash = hash;
    }

    #[wasm_bindgen]
    pub fn derive_seed(&mut self, sk: &[u8], msg: &[u8]) -> Result<(), JsValue> {
        let sk = MusigWasm::read_private_key(sk)?;

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

        let seed = self.seed.ok_or_else(|| JsValue::from("No seed"))?;

        // FIXME
        let generator = FixedGenerators::SpendingKeyGenerator;

        let aggregate_hash = match self.hash {
            MusigHash::SHA256 => Box::new(Sha256HStar {})
        };

        let commitment_hash = match self.hash {
            MusigHash::SHA256 => Box::new(Sha256HStar {})
        };

        let signature_hash = match self.hash {
            MusigHash::SHA256 => Box::new(Sha256HStar {})
        };

        let msg_hash = match self.hash {
            MusigHash::SHA256 => Box::new(Sha256HStar {})
        };

        let session = MusigSession::<Bn256>::new(
            aggregate_hash,
            commitment_hash,
            signature_hash,
            msg_hash,
            generator,
            // TODO: Reuse params?
            AltJubjubBn256::new(),
            self.participants,
            seed,
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

    fn write_fs_repr<W: std::io::Write>(fs_repr: &FsRepr, writer: W) -> Result<(), JsValue> {
        fs_repr.write_be(writer).map_err(MusigWasm::map_error_to_js)
    }

    fn write_fs<W: std::io::Write>(fs: &Fs, writer: W) -> Result<(), JsValue> {
        MusigWasm::write_fs_repr(&fs.into_repr(), writer)
    }

    fn write_private_key_w<W: std::io::Write>(private_key: &PrivateKey<Bn256>, writer: W) -> Result<(), JsValue> {
        MusigWasm::write_fs(&private_key.0, writer)
    }

    fn write_private_key(private_key: &PrivateKey<Bn256>) -> Result<Vec<u8>, JsValue> {
        let mut vec: Vec<u8> = Vec::new();

        MusigWasm::write_private_key_w(private_key, &mut vec).map(|_| {
            vec
        })
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
        MusigWasm::write_public_key_w(public_key, &mut vec).map(|_| {
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

        MusigWasm::write_fs(&res, &mut vec)
            .map(|_| {
                vec
            })
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
        let s = MusigWasm::read_fs(signature)?;

        self.signatures.push(s);

        Ok(())
    }

    #[wasm_bindgen]
    pub fn get_signature(&self) -> Result<Vec<u8>, JsValue> {
        let signature = self.musig
            .aggregate_signature(&self.signatures)
            .map_err(MusigWasm::map_musig_error_to_js)?;

        let mut vec = Vec::new();

        MusigWasm::write_point_w(&signature.r, &mut vec)?;
        MusigWasm::write_fs(&signature.s, &mut vec)?;

        Ok(vec)
    }
}

#[cfg(test)]
mod musig_wasm_unit_tests {
    use crate::musig_wasm::{MusigWasm, MusigWasmUtils};

    #[test]
    fn read_write() {
        let rng = &mut rand::thread_rng();

        let seed = [1usize; 8];

        let sk_data = MusigWasmUtils::generate_private_key(&seed).expect("");

        let sk = MusigWasm::read_private_key(&sk_data[..]).expect("");

        let sk_data2 = MusigWasm::write_private_key(&sk).expect("");

        assert_eq!(sk_data, sk_data2);

        let pk_data = MusigWasmUtils::extract_public_key(&sk_data).expect("");

        let pk = MusigWasm::read_public_key(&pk_data[..]).expect("");

        let pk_data2 = MusigWasm::write_public_key(&pk).expect("");

        assert_eq!(pk_data, pk_data2);
    }
}