use crate::musig_hash::{AggregateHash, CommitmentHash, MsgHash, SignatureHash};
use bellman::pairing::ff::Field;
use franklin_crypto::eddsa::{PrivateKey, PublicKey, Seed, Signature};
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::{FixedGenerators, JubjubEngine, Unknown};

#[derive(Debug)]
pub enum MusigError {
    SelfIndexOutOfBounds,
    AssigningCommitmentToSelfIsForbidden,
    DuplicateCommitmentAssignment,
    AssigningRPubToSelfIsForbidden,
    AssigningRPubBeforeSettingAllCommitmentsIsForbidden,
    DuplicateRPubAssignment,
    RPubDoesntMatchWithCommitment,
    SigningBeforeSettingAllRPubIsForbidden,
    SigningShouldHappenOnlyOncePerSession,
    AggregatingSignatureBeforeSigningIsForbidden,
}

impl MusigError {
    pub fn description(&self) -> &str {
        match *self {
            MusigError::SelfIndexOutOfBounds => "self index is out of bounds",
            MusigError::AssigningCommitmentToSelfIsForbidden => {
                "assigning commitment to self is forbidden"
            }
            MusigError::DuplicateCommitmentAssignment => "duplicate commitment assignment",
            MusigError::AssigningRPubToSelfIsForbidden => "assigning r_pub to self is forbidden",
            MusigError::AssigningRPubBeforeSettingAllCommitmentsIsForbidden => {
                "assigning r_pub before setting all commitments is forbidden"
            }
            MusigError::DuplicateRPubAssignment => "duplicate r_pub assignment",
            MusigError::RPubDoesntMatchWithCommitment => "r_pub doesnt match with commitment",
            MusigError::SigningBeforeSettingAllRPubIsForbidden => {
                "signing before setting all r_pub is forbidden"
            }
            MusigError::SigningShouldHappenOnlyOncePerSession => {
                "signing should happen only once per session"
            }
            MusigError::AggregatingSignatureBeforeSigningIsForbidden => {
                "aggregating signature before signing is forbidden"
            }
        }
    }
}

impl std::error::Error for MusigError {}

impl std::fmt::Display for MusigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.description())
    }
}

pub struct MusigSession<E: JubjubEngine> {
    commitment_hash: Box<dyn CommitmentHash<E>>,
    signature_hash: Box<dyn SignatureHash<E>>,
    msg_hash: Box<dyn MsgHash>,
    participants: Vec<PublicKey<E>>,
    self_index: usize,
    aggregated_public_key: PublicKey<E>,
    a_self: E::Fs,

    r_self: PrivateKey<E>,
    r_pub_aggregated: PublicKey<E>,

    t_participants: Vec<Option<Vec<u8>>>,
    t_count: usize,

    r_pub_participants: Vec<Option<PublicKey<E>>>,
    r_pub_count: usize,

    performed_sign: bool,
}

impl<E: JubjubEngine> MusigSession<E> {
    pub fn new(
        aggregate_hash: Box<dyn AggregateHash<E>>,
        commitment_hash: Box<dyn CommitmentHash<E>>,
        signature_hash: Box<dyn SignatureHash<E>>,
        msg_hash: Box<dyn MsgHash>,
        generator: FixedGenerators,
        params: &E::Params,
        participants: Vec<PublicKey<E>>,
        seed: Seed<E>,
        self_index: usize,
    ) -> Result<MusigSession<E>, MusigError> {
        let number_of_participants = participants.len();

        if self_index >= number_of_participants {
            return Err(MusigError::SelfIndexOutOfBounds);
        }

        let (aggregated_public_key, a_self) = MusigSession::<E>::compute_aggregated_public_key(
            &participants,
            &*aggregate_hash,
            self_index,
            params,
        );

        let (r_self, r_pub_self, t) =
            MusigSession::<E>::generate_commitment(seed, &*commitment_hash, params, generator);

        let mut t_participants = vec![None; number_of_participants];
        t_participants[self_index] = Some(t);

        let mut r_pub_participants = vec![None; number_of_participants];
        r_pub_participants[self_index] = Some(r_pub_self.clone());

        let session = MusigSession {
            commitment_hash,
            signature_hash,
            msg_hash,
            participants,
            self_index,
            aggregated_public_key,
            a_self,
            r_self,
            r_pub_aggregated: r_pub_self,
            t_participants,
            t_count: 1,
            r_pub_participants,
            r_pub_count: 1,
            performed_sign: false,
        };

        Ok(session)
    }

    fn compute_aggregated_public_key(
        participants: &[PublicKey<E>],
        aggregate_hash: &dyn AggregateHash<E>,
        self_index: usize,
        params: &E::Params,
    ) -> (PublicKey<E>, E::Fs) {
        let mut x: Point<E, Unknown> = Point::zero();

        let mut a_self = None;

        for i in 0..participants.len() {
            // TODO: Optimize
            let ai = aggregate_hash.hash(&participants, &participants[i]);

            x = x.add(&participants[i].0.mul(ai, params), params);

            if i == self_index {
                a_self = Some(ai);
            }
        }

        let a_self = a_self.expect("Self index not in range");

        (PublicKey(x), a_self)
    }

    fn generate_commitment(
        seed: Seed<E>,
        commitment_hash: &dyn CommitmentHash<E>,
        params: &E::Params,
        generator: FixedGenerators,
    ) -> (PrivateKey<E>, PublicKey<E>, Vec<u8>) {
        let r = PrivateKey::<E>(seed.0);

        let r_pub = PublicKey::from_private(&r, generator, params);

        let t = commitment_hash.hash(&r_pub);

        (r, r_pub, t)
    }

    pub fn get_self_index(&self) -> usize {
        self.self_index
    }

    pub fn get_t(&self) -> &Vec<u8> {
        self.t_participants[self.self_index]
            .as_ref()
            .expect("Commitment is absent")
    }

    pub fn get_r_pub(&self) -> &PublicKey<E> {
        self.r_pub_participants[self.self_index]
            .as_ref()
            .expect("R_pub is absent")
    }

    pub fn get_aggregated_public_key(&self) -> &PublicKey<E> {
        &self.aggregated_public_key
    }

    pub fn set_t(&mut self, t: &[u8], index: usize) -> Result<(), MusigError> {
        if self.self_index == index {
            return Err(MusigError::AssigningCommitmentToSelfIsForbidden);
        }

        if self.t_participants[index].is_some() {
            return Err(MusigError::DuplicateCommitmentAssignment);
        }

        self.t_participants[index] = Some(Vec::from(t));
        self.t_count += 1;

        Ok(())
    }

    pub fn set_r_pub(&mut self, r_pub: PublicKey<E>, index: usize, params: &E::Params) -> Result<(), MusigError> {
        if self.self_index == index {
            return Err(MusigError::AssigningRPubToSelfIsForbidden);
        }

        if self.t_count != self.participants.len() {
            return Err(MusigError::AssigningRPubBeforeSettingAllCommitmentsIsForbidden);
        }

        if self.r_pub_participants[index].is_some() {
            return Err(MusigError::DuplicateRPubAssignment);
        }

        let t_real = self.commitment_hash.hash(&r_pub);

        if !self.t_participants[index]
            .as_ref()
            .expect("Commitment is absent during check")
            .eq(&t_real)
        {
            return Err(MusigError::RPubDoesntMatchWithCommitment);
        }

        self.r_pub_aggregated = PublicKey {
            0: self.r_pub_aggregated.0.add(&r_pub.0, params),
        };

        self.r_pub_participants[index] = Some(r_pub);
        self.r_pub_count += 1;

        Ok(())
    }

    pub fn sign(&mut self, sk: &PrivateKey<E>, m: &[u8]) -> Result<E::Fs, MusigError> {
        if self.r_pub_count != self.participants.len() {
            return Err(MusigError::SigningBeforeSettingAllRPubIsForbidden);
        }

        if self.performed_sign {
            return Err(MusigError::SigningShouldHappenOnlyOncePerSession);
        }

        let msg_hash = self.msg_hash.hash(m);

        let mut s = self.signature_hash.hash(
            &self.aggregated_public_key,
            &self.r_pub_aggregated,
            &msg_hash,
        );

        s.mul_assign(&self.a_self);
        s.mul_assign(&sk.0);
        s.add_assign(&self.r_self.0);

        self.performed_sign = true;

        Ok(s)
    }

    pub fn aggregate_signature(
        &self,
        participant_signatures: &[E::Fs],
    ) -> Result<Signature<E>, MusigError> {
        assert!(!participant_signatures.is_empty());

        if !self.performed_sign {
            return Err(MusigError::AggregatingSignatureBeforeSigningIsForbidden);
        }

        let mut s = E::Fs::zero();

        for s_participant in participant_signatures {
            s.add_assign(s_participant);
        }

        Ok(Signature {
            r: self.r_pub_aggregated.0.clone(),
            s,
        })
    }
}

pub struct MusigVerifier {
    msg_hash: Box<dyn MsgHash>,
    generator: FixedGenerators,
}

impl MusigVerifier {
    pub fn new(
        msg_hash: Box<dyn MsgHash>,
        generator: FixedGenerators,
    ) -> MusigVerifier {
        MusigVerifier {
            msg_hash,
            generator,
        }
    }

    pub fn verify_signature<E: JubjubEngine>(
        &self,
        signature: &Signature<E>,
        msg: &[u8],
        aggregated_public_key: &PublicKey<E>,
        params: &E::Params,
    ) -> bool {
        let msg_hash = self.msg_hash.hash(msg);

        aggregated_public_key.verify_musig_sha256(
            &msg_hash,
            signature,
            self.generator,
            params,
        )
    }
}
