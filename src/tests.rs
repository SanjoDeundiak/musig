#[cfg(test)]
mod tests {
    use crate::musig::MusigSession;
    use crate::musig_hash::Sha256HStar;
    use rand::{thread_rng, Rng};
    use franklin_crypto::eddsa::{PrivateKey, PublicKey};
    use franklin_crypto::alt_babyjubjub::{FixedGenerators, AltJubjubBn256};
    use bellman::pairing::bn256::Bn256;

    struct SplitIterator<'a, T> {
        index: usize,
        left: &'a mut [T],
        right: &'a mut [T],
    }

    impl<'a, T> SplitIterator<'a, T> {
        fn new(left: &'a mut [T],
               right: &'a mut [T]) -> SplitIterator<'a, T> {
            SplitIterator {
                index: 0,
                left,
                right
            }
        }

        fn next(&mut self) -> Option<&mut T> {
            let res;

            if self.index < self.left.len() {
                res = Some(&mut self.left[self.index]);
            }
            else if self.index < self.left.len() + self.right.len() {
                res = Some(&mut self.right[self.index - self.left.len()]);
            }
            else {
                res = None
            }

            self.index += 1;

            res
        }
    }

    fn split_slice_at_inclusive<T>(slice: &mut [T], mid: usize) -> (SplitIterator<T>, &T) {
        let len = slice.len();
        let ptr = slice.as_mut_ptr();

        unsafe {
            assert!(mid < len);

            (SplitIterator::new(std::slice::from_raw_parts_mut(ptr, mid), std::slice::from_raw_parts_mut(ptr.add(mid + 1),  len - mid - 1)),
             &mut *ptr.add(mid))
        }
    }

    type E = Bn256;

    fn create_sessions(rng: &mut impl Rng,
                       n: usize,
                       generator: FixedGenerators,
                       params: &AltJubjubBn256) -> (Vec<MusigSession<E>>,
                                               Vec<PrivateKey<E>>) {
        let mut participants_sk: Vec<PrivateKey<E>> = Vec::new();
        let mut participants_pk: Vec<PublicKey<E>> = Vec::new();

        // Everybody generates key pairs
        for _ in 0..n {
            let sk = PrivateKey::<E>(rng.gen());

            let pk: PublicKey<E> = PublicKey::from_private(&sk, generator, &params);

            participants_sk.push(sk);
            participants_pk.push(pk);
        }

        // Everybody creates MusigSession
        let mut sessions: Vec<MusigSession<E>> = Vec::new();

        for i in 0..n {
            let participants_copy: Vec<PublicKey<E>> = participants_pk.clone();

            let session: MusigSession<E> = MusigSession::new(rng,
                                                             Box::new(Sha256HStar {}),
                                                             Box::new(Sha256HStar {}),
                                                             Box::new(Sha256HStar {}),
                                                             generator,
                                                             AltJubjubBn256::new(),
                                                             participants_copy,
                                                             i).expect("");

            sessions.push(session);
        }

        (sessions, participants_sk)
    }

    fn sign_and_verify_random_message(n: usize) {
        let params = AltJubjubBn256::new();
        let generator = FixedGenerators::ProofGenerationKey;

        let mut rng = &mut thread_rng();

        let (mut sessions, participants_sk) = create_sessions(&mut rng, n, generator, &params);

        let aggregated_public_key = sessions[0].get_aggregated_public_key().clone();

        // Checking that each party ended up deriving the same key
        for i in 1..n {
            let key = sessions[i].get_aggregated_public_key();

            assert!(key.0.eq(&aggregated_public_key.0))
        }

        // Commitments exchange stage
        for i in 0..n {
            let (mut iterator, mid) = split_slice_at_inclusive(&mut sessions, i);

            let t = mid.get_t();

            loop {
                let session = match iterator.next() {
                    Some(e) => e,
                    None => break,
                };

                session.set_t(t, mid.get_self_index()).expect("");
            }
        }

        // Reveal stage
        for i in 0..n {
            let (mut iterator, mid) = split_slice_at_inclusive(&mut sessions, i);

            let r_pub = mid.get_r_pub();

            loop {
                let session = match iterator.next() {
                    Some(e) => e,
                    None => break,
                };

                session.set_r_pub(r_pub.clone(), mid.get_self_index()).expect("");
            }
        }

        let mut m = [0; 32];
        rng.fill_bytes(&mut m);

        let mut s = Vec::new();

        for i in 0..n {
            s.push((&mut sessions[i]).sign(&participants_sk[i], &m).expect(""));
        }

        let signature = sessions[0].aggregate_signature(&s).expect("");

        for i in 0..n {
            let signature1 = sessions[i].aggregate_signature(&s).expect("");

            assert!(signature.r.eq(&signature1.r));
            assert!(signature.s.eq(&signature1.s));
        }

        assert!(aggregated_public_key.verify_musig_sha256(&m, &signature, generator, &params));
    }

    #[test]
    fn sign_verify__5_signers__should_verity() {
        sign_and_verify_random_message(5);
    }

    #[test]
    fn sign_verify__1_signer__should_verity() {
        sign_and_verify_random_message(1);
    }
}