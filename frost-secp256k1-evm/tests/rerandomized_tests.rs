use frost_secp256k1_evm::Secp256K1Keccak256;

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = rand::rngs::OsRng;

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<Secp256K1Keccak256, _>(rng);
}
