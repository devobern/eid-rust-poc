use std::collections::BTreeMap;

use bbs::issuer::Issuer;
use bbs::prelude::*;
use sha2::{Digest, Sha256};

#[macro_use]
extern crate serde_json;

fn main() {
    // Specify the number of messages the keys should be able to sign
    let message_count = 5; 

    let signature_blinding = Signature::generate_blinding();

    // Call `create_keys` and handle any potential errors
    match create_keys(message_count) {
        Ok((public_key, secret_key)) => {
            println!("Public Key: {:?}", public_key);
            println!("Secret Key: {:?}", secret_key);
            
            // Example eID JSON document
            let eid_data = json!({
                "name": "Max Musterman",
                "date_of_birth": "1970-01-01",
                "eid_number": "123456789",
                "expiration_date": "2030-01-01"
            });

            // Convert the JSON document to messages suitable for signing
            let messages = json_to_messages(&eid_data);

            let commitment = create_commitment(&public_key, &signature_blinding);
            println!("Commitment: {:?}", commitment);

            // Sign the messages
            match blind_sign_messages(&messages, &secret_key, &public_key, &commitment) {
                Ok(blinded_signature) => {

                    println!("Signature: {:?}", blinded_signature);
                    // The signature can now be used to verify the signed eID data
                    let unblinded_signature = unblind_signature(&blinded_signature, &signature_blinding);
                    println!("Unblinded Signatur: {:}", unblinded_signature);

                    let proof_request = create_proof_request(&public_key);

                    let nonce = Verifier::generate_proof_nonce();
                    let pok = create_proof_of_knowledge(&proof_request, &messages, &unblinded_signature, &nonce);

                    let check = check_signature_pok(&proof_request, &pok, &nonce);
                    println!("Verify result: {:?}", check);
                },
                Err(e) => eprintln!("Failed to sign messages: {:?}", e),
            }
        },
        Err(e) => {
            eprintln!("Failed to create keys: {:?}", e);
            // Handle the error appropriately
        }
    }

}


fn create_keys(message_count: usize) -> Result<(PublicKey, SecretKey), BBSError> {
    Issuer::new_keys(message_count)
}

fn json_to_messages(eid_data: &serde_json::Value) -> Vec<SignatureMessage> {
    eid_data.as_object().unwrap().iter().map(|(_, value)| {
        let data_str = value.as_str().unwrap();
        let hash = Sha256::digest(data_str.as_bytes());
        SignatureMessage::hash(&hash)
    }).collect()
}

fn blind_sign_messages(messages: &[SignatureMessage], secret_key: &SecretKey, public_key: &PublicKey, commitment: &Commitment) -> Result<BlindSignature, BBSError> {
    // Do we not need this?
    // let mut rng = rand::thread_rng();
    let mut messages_map = BTreeMap::new();
    messages_map.insert(0, SignatureMessage::hash(b"password"));
    for i in 0..messages.len() {
        messages_map.insert(i+1, messages[i]);
    }
    BlindSignature::new(commitment, &messages_map, secret_key, public_key)
    
}

fn create_commitment(public_key: &PublicKey, signature_blinding: &SignatureBlinding) -> Commitment {
    let password = SignatureMessage::hash(b"password");
    // &public_key.h[0] * &password + &public_key.h0 * &signature_blinding
    let mut builder = CommitmentBuilder::new();
    builder.add(public_key.h0.clone(), &signature_blinding);
    builder.add(public_key.h[0].clone(), &password);
    builder.finalize()
}

fn unblind_signature(blinded_signature: &BlindSignature, signature_blinding: &SignatureBlinding) -> Signature {
    blinded_signature.to_unblinded(signature_blinding)
}

fn create_proof_request(public_key: &PublicKey) -> ProofRequest {
    Verifier::new_proof_request(&[1,3], public_key).unwrap()
}

fn create_proof_of_knowledge(proof_request: &ProofRequest, messages: &[SignatureMessage], signature: &Signature, nonce: &ProofNonce) -> SignatureProof{
    let proof_messages = vec![
        ProofMessage::Hidden((HiddenMessage::ProofSpecificBlinding(SignatureMessage::hash(b"password")))),
        ProofMessage::Revealed(messages[0]),
        ProofMessage::Hidden((HiddenMessage::ProofSpecificBlinding(messages[1]))),
        ProofMessage::Revealed(messages[2]),
        ProofMessage::Hidden((HiddenMessage::ProofSpecificBlinding(messages[3]))),
    ];

    let pok = Prover::commit_signature_pok(proof_request, proof_messages.as_slice(), signature).unwrap();

    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
    challenge_bytes.extend_from_slice(nonce.to_bytes_compressed_form().as_slice());

    let challenge = ProofChallenge::hash(&challenge_bytes);

    Prover::generate_signature_pok(pok, &challenge).unwrap()

}

fn check_signature_pok(proof_request: &ProofRequest, proof: &SignatureProof, nonce: &ProofNonce) -> bool {
    match Verifier::verify_signature_pok(proof_request, proof, nonce) {
        Ok(_) => return true,
        Err(_) => return false
    }
}