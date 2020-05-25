mod musig_wasm_tests {
    use byte_slice_cast::*;
    use musig_wasm::musig_wasm::MusigWasm;
    use musig_wasm::hash_alg::HashAlg;
    use musig_wasm::builder::Builder;
    use musig_wasm::utils::Utils;
    use musig_wasm::signature_verifier::SignatureVerifier;
    use rand::{thread_rng, Rng};

    fn create_sessions(rng: &mut impl Rng, msg: &[u8], n: usize) -> (Vec<MusigWasm>, Vec<Vec<u8>>) {
        let mut participants_sk: Vec<Vec<u8>> = Vec::new();
        let mut participants_pk: Vec<Vec<u8>> = Vec::new();

        // Everybody generates key pairs
        for _ in 0..n {
            let mut seed = [0u8; 32];

            rng.fill_bytes(&mut seed);

            let s = seed.as_slice_of::<usize>().expect("");

            let sk = Utils::generate_private_key(s).expect("");

            let pk = Utils::extract_public_key(&sk).expect("");

            participants_sk.push(sk);
            participants_pk.push(pk);
        }

        // Everybody creates MusigSession
        let mut sessions: Vec<MusigWasm> = Vec::new();

        for i in 0..n {
            let mut builder = Builder::new();

            builder.derive_seed(&participants_sk[i], msg).expect("");

            for j in 0..n {
                builder
                    .add_participant(&participants_pk[j], i == j)
                    .expect("");
            }

            sessions.push(builder.build().expect(""));
        }

        (sessions, participants_sk)
    }

    fn sign_and_verify_random_message(n: usize) {
        let mut rng = &mut thread_rng();

        let mut size = rng.gen();
        size = size % 1024 + 32;

        let mut msg: Vec<u8> = vec![0; size];
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
            let t = sessions[i].get_t();

            for (j, session) in sessions.iter_mut().enumerate() {
                if i == j {
                    continue;
                }

                session.set_t(&t, i).expect("");
            }
        }

        // Reveal stage
        for i in 0..n {
            let r_pub = sessions[i].get_r_pub().expect("");

            for (j, session) in sessions.iter_mut().enumerate() {
                if i == j {
                    continue;
                }
                session.set_r_pub(&r_pub, i).expect("");
            }
        }

        let mut signatures = Vec::new();

        for i in 0..n {
            signatures.push(
                (&mut sessions[i])
                    .sign(&participants_sk[i], &msg)
                    .expect(""),
            );
        }

        let mut signature_aggregator = sessions.pop().expect("").build_signature_aggregator();

        for i in 0..n {
            signature_aggregator
                .add_signature(&signatures[i])
                .expect("")
        }

        let signature = signature_aggregator.get_signature().expect("");

        let verifier = SignatureVerifier::new(HashAlg::SHA256);

        let verified = verifier
            .verify(&msg, &aggregated_public_key, &signature)
            .expect("");

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
