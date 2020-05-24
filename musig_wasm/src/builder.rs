use musig::musig::MusigSession;
use musig::hash::Sha256HStar;
use bellman::pairing::bn256::Bn256;
use franklin_crypto::alt_babyjubjub::FixedGenerators;
use franklin_crypto::eddsa::{PublicKey, Seed};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use crate::musig_wasm::{MusigWasm, JUBJUB_PARAMS};
use crate::wasm_formats::WasmFormats;
use crate::hash_alg::HashAlg;

pub const PACKED_POINT_SIZE: usize = 32;
pub const FS_SIZE: usize = 32;

#[wasm_bindgen(js_name = "MusigWasmBuilder")]
pub struct Builder {
    participants: Vec<PublicKey<Bn256>>,
    seed: Option<Seed<Bn256>>,
    self_index: usize,
    set_self_index: bool,
    hash: HashAlg,
}

#[wasm_bindgen(js_class = "MusigWasmBuilder")]
impl Builder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Builder {
            participants: Vec::new(),
            seed: None,
            self_index: 0,
            set_self_index: false,
            hash: HashAlg::SHA256,
        }
    }

    #[wasm_bindgen(js_name = "setAllHashes")]
    pub fn set_all_hashes(&mut self, hash: HashAlg) {
        self.hash = hash;
    }

    #[wasm_bindgen(js_name = "deriveSeed")]
    pub fn derive_seed(&mut self, sk: &[u8], msg: &[u8]) -> Result<(), JsValue> {
        let sk = WasmFormats::read_private_key(sk)?;

        let hashed_msg = match self.hash {
            HashAlg::SHA256 => {
                Sha256::digest(msg).to_vec()
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

        let key = WasmFormats::read_public_key(participant_public_key, &JUBJUB_PARAMS)?;

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
            HashAlg::SHA256 => Box::new(Sha256HStar {}),
        };

        let commitment_hash = match self.hash {
            HashAlg::SHA256 => Box::new(Sha256HStar {}),
        };

        let signature_hash = match self.hash {
            HashAlg::SHA256 => Box::new(Sha256HStar {}),
        };

        let msg_hash = match self.hash {
            HashAlg::SHA256 => Box::new(Sha256HStar {}),
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
            .map_err(WasmFormats::map_error_to_js)?;

        Ok(MusigWasm::new(session))
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}