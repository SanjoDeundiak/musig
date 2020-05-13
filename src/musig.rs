use crate::musig_hash::{AggregateHash, CommitmentHash, SignatureHash};
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::eddsa::{PublicKey, PrivateKey, Signature};
use franklin_crypto::jubjub::{Unknown, JubjubEngine, FixedGenerators};
use bellman::pairing::ff::Field;
use rand::thread_rng;
use rand::Rng;

pub struct MusigSession<E: JubjubEngine> {
    commitment_hash: Box<dyn CommitmentHash<E>>,
    signature_hash: Box<dyn SignatureHash<E>>,
    params: E::Params,
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
    pub fn new(aggregate_hash: Box<dyn AggregateHash<E>>,
               commitment_hash: Box<dyn CommitmentHash<E>>,
               signature_hash: Box<dyn SignatureHash<E>>,
               generator: FixedGenerators,
               params: E::Params,
               participants: Vec<PublicKey<E>>,
               self_index: usize) -> MusigSession<E> {
        let number_of_participants = participants.len();

        let (aggregated_public_key, a_self) = MusigSession::<E>::compute_aggregated_public_key(&participants, &*aggregate_hash, self_index, &params);


        let (r_self, r_pub_self, t) = MusigSession::<E>::generate_commitment(&*commitment_hash, &params, generator);

        let mut t_participants = vec![None; number_of_participants];
        t_participants[self_index] = Some(t);

        let mut r_pub_participants = vec![None; number_of_participants];
        r_pub_participants[self_index] = Some(r_pub_self.clone());


        let session = MusigSession {
            commitment_hash,
            signature_hash,
            params,
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

        session
    }

    fn compute_aggregated_public_key(participants: &Vec<PublicKey<E>>,
                                     aggregate_hash: &dyn AggregateHash<E>,
                                     self_index: usize,
                                     params: &E::Params) -> (PublicKey<E>, E::Fs) {
        assert!(self_index < participants.len());

        let mut x: Point<E, Unknown> = Point::zero();

        let mut a_self = None;
        let mut ai_vec = participants.clone();

        for i in 0..participants.len() {
            let public_key = &participants[i];

            ai_vec.push(public_key.clone());

            let ai = aggregate_hash.hash(&ai_vec);

            ai_vec.pop();

            x = x.add(&public_key.0.mul(ai, params), params);

            if i == self_index {
                a_self = Some(ai.clone());
            }
        }

        let a_self = match a_self {
            Some(a) => a,
            None => panic!("FIXME"),
        };

        (PublicKey(x), a_self)
    }

    fn generate_commitment(commitment_hash: &dyn CommitmentHash<E>,
                           params: &E::Params,
                           generators: FixedGenerators) -> (PrivateKey::<E>, PublicKey<E>, Vec<u8>) {
        // FIXME
        // let rng: StdRng = SeedableRng::from_entropy();

        let rng = &mut thread_rng();
        let r = PrivateKey::<E>(rng.gen());

        let r_pub = PublicKey::from_private(&r,
                                            generators,
                                            params);

        let t = commitment_hash.hash(&r_pub);

        (r, r_pub, t)
    }

    pub fn get_self_index(&self) -> usize {
        self.self_index
    }

    pub fn get_t(&self) -> &Vec<u8> {
        match &self.t_participants[self.self_index] {
            Some(t) => return t,
            None => panic!("FIXME Should not happen")
        }
    }

    pub fn get_r_pub(&self) -> &PublicKey<E> {
        match &self.r_pub_participants[self.self_index] {
            Some(r_pub) => return r_pub,
            None => panic!("FIXME Should not happen")
        }
    }

    pub fn get_aggregated_public_key(&self) -> &PublicKey<E> {
        &self.aggregated_public_key
    }

    pub fn set_t(&mut self, t: &[u8], index: usize) {
        assert_ne!(self.self_index, index);

        if self.t_participants[index].is_some() {
            panic!("FIXME")
        }

        self.t_participants[index] = Some(Vec::from(t));
        self.t_count += 1;
    }

    pub fn set_r_pub(&mut self, r_pub: PublicKey<E>, index: usize) {
        assert_ne!(self.self_index, index); // FIXME

        if self.t_count != self.participants.len() {
            panic!("FIXME")
        }

        if self.r_pub_participants[index].is_some() {
            panic!("FIXME")
        }

        let t_real = self.commitment_hash.hash(&r_pub);

        match &self.t_participants[index] {
            Some(t) => assert!(t.eq(&t_real)), // FIXME
            None => panic!("FIXME")
        }

        self.r_pub_aggregated = PublicKey { 0: self.r_pub_aggregated.0.add(&r_pub.0, &self.params) };

        self.r_pub_participants[index] = Some(r_pub);
        self.r_pub_count += 1;
    }

    pub fn sign(&mut self, sk: &PrivateKey<E>, m: &[u8]) -> E::Fs {
        if self.r_pub_count != self.participants.len() {
            panic!("FIXME")
        }

        if self.performed_sign {
            panic!("Signature is only performed once per session");
        }

        let mut s= self.signature_hash.hash(&self.aggregated_public_key, &self.r_pub_aggregated, m);

        s.mul_assign(&self.a_self);
        s.mul_assign(&sk.0);
        s.add_assign(&self.r_self.0);

        self.performed_sign = true;

        s
    }

    pub fn aggregate_signature(&self, participant_signatures: &[E::Fs]) -> Signature<E> {
        if !self.performed_sign {
            panic!("FIXME");
        }

        let mut s = E::Fs::zero();

        for s_participant in participant_signatures {
            s.add_assign(s_participant);
        }

        Signature {
            r: self.r_pub_aggregated.0.clone(),
            s
        }
    }
}