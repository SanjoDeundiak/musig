use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = "MusigHashAlg")]
pub enum HashAlg {
    SHA256,
}