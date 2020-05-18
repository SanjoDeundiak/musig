#[cfg(test)]
mod musig_wasm_tests {
    use musig::musig_wasm::{MusigWasm, MusigWasmUtils, MusigWasmBuilder, MusigWasmVerifier};
    use rand::{thread_rng, Rng};
    use byte_slice_cast::*;

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

    fn create_sessions(rng: &mut impl Rng,
                       msg: &[u8],
                       n: usize) -> (Vec<MusigWasm>,
                                     Vec<Vec<u8>>) {
        let mut participants_sk: Vec<Vec<u8>> = Vec::new();
        let mut participants_pk: Vec<Vec<u8>> = Vec::new();

        // Everybody generates key pairs
        for _ in 0..n {
            // FIXME: Hard code
            let mut seed = [0u8; 32];

            rng.fill_bytes(&mut seed);

            let s = seed.as_slice_of::<usize>().expect("");

            let sk = MusigWasmUtils::generate_private_key(s).expect("");

            let pk = MusigWasmUtils::extract_public_key(&sk).expect("");

            participants_sk.push(sk);
            participants_pk.push(pk);
        }

        // Everybody creates MusigSession
        let mut sessions: Vec<MusigWasm> = Vec::new();

        for i in 0..n {
            let mut builder = MusigWasmBuilder::new();

            builder.derive_seed(&participants_sk[i], msg).expect("");

            for j in 0..n {
                builder.add_participant(&participants_pk[j], i == j).expect("");
            }

            sessions.push(builder.build().expect(""));
        }

        (sessions, participants_sk)
    }

    fn sign_and_verify_random_message(n: usize) {
        let mut rng = &mut thread_rng();

        let mut size = rng.gen();
        size = size % 1024 + 32;

        let mut msg: Vec<u8> = vec!(0; size);
        rng.fill_bytes(&mut msg);

        let (mut sessions, participants_sk) = create_sessions(&mut rng, &msg, n);

        let aggregated_public_key = sessions[0].get_aggregated_public_key().expect("");

        // Checking that each party ended up deriving the same key
        for i in 1..n {
            let key = sessions[i].get_aggregated_public_key().expect("");

            assert_eq!(&key, &aggregated_public_key)
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

                session.set_t(&t, mid.get_self_index()).expect("");
            }
        }

        // Reveal stage
        for i in 0..n {
            let (mut iterator, mid) = split_slice_at_inclusive(&mut sessions, i);

            let r_pub = mid.get_r_pub().expect("");

            loop {
                let session = match iterator.next() {
                    Some(e) => e,
                    None => break,
                };

                session.set_r_pub(&r_pub, mid.get_self_index()).expect("");
            }
        }

        let mut signatures = Vec::new();

        for i in 0..n {
            signatures.push((&mut sessions[i]).sign(&participants_sk[i], &msg).expect(""));
        }

        let mut signature_aggregator = sessions.pop().expect("").build_signature_aggregator();

        for i in 0..n {
            signature_aggregator.add_signature(&signatures[i]).expect("")
        }

        let signature = signature_aggregator.get_signature().expect("");

        let verifier = MusigWasmVerifier::new();

        let verified = verifier.verify(&msg, &aggregated_public_key, &signature).expect("");

        assert!(verified);
    }

    #[test]
    fn sign_verify__5_signers__should_verify() {
        sign_and_verify_random_message(5);
    }

    #[test]
    fn sign_verify__1_signer__should_verify() {
        sign_and_verify_random_message(1);
    }
}