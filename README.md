## Rust "Simple Schnorr Multi-Signatures"

## Paper
https://eprint.iacr.org/2018/068.pdf

## Usage

Preliminaries:
 - Each signer owns static key pair which will be used for this signature
 - Each signer knows public keys of other signers
 - Each signer is given unique index (0 <= index < n, n - number of signers)
 - Signers agreed on common storage (further - server)
 - Signers agreed on message that will be signed
 
## Flow:

### Rust

1. Each signer (i) creates MusigSession instance
    ```rust
    type E = Bn256;
    let params = AltJubjubBn256::new();
    let generator = FixedGenerators::SpendingKeyGenerator;
   
    let mut rng = &mut thread_rng();
    let seed = Seed::<Bn256>(rng.gen());
   
    let session_i = MusigSession::<E>::new(Box::new(Sha256HStar {}), // Aggregate hash
                                           Box::new(Sha256HStar {}), // Commitment hash
                                           Box::new(Sha256HStar {}), // Signature hash
                                           Box::new(Sha256HStar {}), // MessageHash
                                           generator,
                                           AltJubjubBn256::new(),
                                           [public_key0, public_key1, ..],
                                           seed,
                                           i).expect("");
    ```

1. Get aggregated public key which will be used for verification
    ```rust
    let aggregated_public_key = session_i.get_aggregated_public_key().clone();
    ```
   
   Each signer will get same value from this function

1. Each signer (i) should upload its commitment (t) to the server
    ```rust
    let t_i = session_i.get_t();
    // Send t to the server 
    ```
   
1. Each signer (i) should get commitments (t) from all of other signers
    ```rust
    for j in 0..n {
        if j == i {
            continue;
        }
        session_i.set_t(t_j, j).expect(""); 
    }
    ```
   
1. Each signer (i) reveals his R (sends it to the server)
    ```rust
    let r_pub_i = session_i.get_r_pub();
    // Send r_pub_i to the server
    ``` 

1. Each signer (i) should get R from all of other signers
    ```rust
    for j in 0..n {
        if j == i {
            continue;
        }
        session_i.set_r_pub(r_pub_j, j).expect("");
    }
    ```
   
1. Each signer (i) produces his part of the signature (s) and pushes it to the server
    ```rust
    let s_i = session_i.sign(&signer_private_key_i, &message).expect("");
    // Send s_i to the server
    ```
   
1. Any (or all) of the signers can now aggregate parts into final signature
    ```rust
    let signature = session.aggregate_signature([s0, s1, ..]).expect("");
    ```
   
1. Signature can now be verified
    ```rust
    let verifier = MusigVerifier::<E>::new(Box::new(Sha256HStar {}), // Message hash
                                           generator,
                                           AltJubjubBn256::new());
   
    verifier.verify_signature(&signature, &message, &aggregated_public_key);
    ```
   
### JS

1. Each signer (i) creates MusigSession instance
    ```js
    import * as wasm from "musig";
    import {MusigWasmVerifier, MusigWasm} from "musig";
    
    let builder_i = new wasm.MusigWasmBuilder();
    for (let j = 0; j < n; j++) {
        builder_i.add_participant(public_key_i, i === j);
    }
   
    builder_i.derive_seed(signer_private_key_i, message);
   
    let session_i = builder_i.build();
    ```

1. Get aggregated public key which will be used for verification
    ```rust
    let aggregatedPublicKey = sessions_i.get_aggregated_public_key();
    ```
   
   Each signer will get same value from this function

1. Each signer (i) should upload its commitment (t) to the server
    ```rust
    let t_i = session_i.get_t();
    // Send t to the server 
    ```
   
1. Each signer (i) should get commitments (t) from all of other signers
    ```rust
    for (let j = 0; j < n; j++) {
        if j == i {
            continue;
        }
        session_i.set_t(t_j, j); 
    }
    ```
   
1. Each signer (i) reveals his R (sends it to the server)
    ```rust
    let r_pub_i = session_i.get_r_pub();
    // Send r_pub_i to the server
    ``` 

1. Each signer (i) should get R from all of other signers
    ```rust
    for (let j = 0; j < n; j++) {
        if j == i {
            continue;
        }
        session_i.set_r_pub(r_pub_j, j); 
    }
    ```
   
1. Each signer (i) produces his part of the signature (s) and pushes it to the server
    ```rust
    let s_i = session_i.sign(signer_private_key_i, &message);
    // Send s_i to the server
    ```
   
1. Any (or all) of the signers can now aggregate parts into final signature
    ```rust
    let aggregator = sessions_i.build_signature_aggregator();
    for (let i = 0; i < n; i++) {
        aggregator.add_signature(s_i);
    }
    
    let signature = aggregator.get_signature();
    ```
   
1. Signature can now be verified
    ```rust
    let verifier = MusigWasmVerifier.new();
    
    let verified = verifier.verify(message, aggregatedPublicKey, signature);
    ```