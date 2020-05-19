use bellman::pairing::ff::{PrimeField, PrimeFieldRepr};
use franklin_crypto::eddsa::PublicKey;
use franklin_crypto::jubjub::JubjubEngine;
use franklin_crypto::util::sha256_hash_to_scalar;
use sha2::{Digest, Sha256};

pub trait AggregateHash<E: JubjubEngine> {
    fn hash(&self, pubs: &[PublicKey<E>], last: &PublicKey<E>) -> E::Fs;
}

pub trait CommitmentHash<E: JubjubEngine> {
    fn hash(&self, r_pub: &PublicKey<E>) -> Vec<u8>;
}

pub trait SignatureHash<E: JubjubEngine> {
    fn hash(&self, x_pub: &PublicKey<E>, r_pub: &PublicKey<E>, m: &[u8]) -> E::Fs;
}

pub trait MsgHash {
    fn hash(&self, m: &[u8]) -> Vec<u8>;
}

#[derive(Clone)]
pub struct Sha256HStar {}

impl Sha256HStar {
    fn write_public_key<E: JubjubEngine>(public_key: &PublicKey<E>, dest: &mut Vec<u8>) {
        let (pk_x, _) = public_key.0.into_xy();
        let mut pk_x_bytes = [0u8; 32];
        pk_x.into_repr()
            .write_le(&mut pk_x_bytes[..])
            .expect("has serialized pk_x");

        dest.extend_from_slice(&pk_x_bytes);
    }
}

impl<E: JubjubEngine> SignatureHash<E> for Sha256HStar {
    fn hash(&self, x_pub: &PublicKey<E>, r_pub: &PublicKey<E>, m: &[u8]) -> E::Fs {
        let mut concatenated: Vec<u8> = Vec::new();
        Sha256HStar::write_public_key(x_pub, &mut concatenated);
        Sha256HStar::write_public_key(r_pub, &mut concatenated);

        let mut msg_padded: Vec<u8> = m.to_vec();
        msg_padded.resize(32, 0u8);

        sha256_hash_to_scalar::<E>(&[], &concatenated, &msg_padded)
    }
}

impl<E: JubjubEngine> AggregateHash<E> for Sha256HStar {
    fn hash(&self, pubs: &[PublicKey<E>], last: &PublicKey<E>) -> <E as JubjubEngine>::Fs {
        let mut concatenated: Vec<u8> = Vec::new();

        for pub_key in pubs {
            Sha256HStar::write_public_key(pub_key, &mut concatenated);
        }

        Sha256HStar::write_public_key(last, &mut concatenated);

        sha256_hash_to_scalar::<E>(&[], &[], &concatenated)
    }
}

impl<E: JubjubEngine> CommitmentHash<E> for Sha256HStar {
    fn hash(&self, r_pub: &PublicKey<E>) -> Vec<u8> {
        let mut concatenated: Vec<u8> = Vec::new();

        Sha256HStar::write_public_key(r_pub, &mut concatenated);

        let mut hasher = Sha256::default();
        hasher.input(&concatenated);

        hasher.result().to_vec()
    }
}

impl MsgHash for Sha256HStar {
    fn hash(&self, m: &[u8]) -> Vec<u8> {
        let mut hash = Sha256::default();

        hash.input(m);

        hash.result().to_vec()
    }
}
