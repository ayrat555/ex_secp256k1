use rustler::types::binary::{Binary, OwnedBinary};
use rustler::{Encoder, Env, Term};
use secp256k1::curve::Scalar;
use secp256k1::{Message, PublicKey, RecoveryId, SecretKey, Signature};

mod atoms {
    rustler::atoms! {
        ok,
        error,
        wrong_message_size,
        wrong_private_key_size,
        wrong_hash_size,
        wrong_r_size,
        wrong_s_size,
        wrong_signature_size,
        recovery_failure,
        invalid_recovery_id
    }
}

rustler::init!(
    "Elixir.ExSecp256k1",
    [
        sign,
        sign_compact,
        recover,
        recover_compact,
        create_public_key
    ]
);

#[rustler::nif]
fn sign<'a>(env: Env<'a>, message_bin: Binary, private_key_bin: Binary) -> Term<'a> {
    let (Signature { s, r }, recid) = match secp256k1_sign(env, message_bin, private_key_bin) {
        Ok(result) => result,
        Err(error) => return error,
    };

    let mut r_bin: OwnedBinary = OwnedBinary::new(32).unwrap();
    let mut s_bin: OwnedBinary = OwnedBinary::new(32).unwrap();

    r_bin.as_mut_slice().copy_from_slice(&r.b32());
    s_bin.as_mut_slice().copy_from_slice(&s.b32());
    let recid_u8: u8 = recid.into();

    (
        atoms::ok(),
        (r_bin.release(env), s_bin.release(env), recid_u8),
    )
        .encode(env)
}

#[rustler::nif]
fn sign_compact<'a>(env: Env<'a>, message_bin: Binary, private_key_bin: Binary) -> Term<'a> {
    let (signature, recovery_id) = match secp256k1_sign(env, message_bin, private_key_bin) {
        Ok((result, recovery_id)) => (result.serialize(), recovery_id.serialize()),
        Err(error) => return error,
    };

    let mut signature_bin: OwnedBinary = OwnedBinary::new(64).unwrap();

    signature_bin.as_mut_slice().copy_from_slice(&signature);

    (atoms::ok(), (signature_bin.release(env), recovery_id)).encode(env)
}

#[rustler::nif]
fn recover<'a>(
    env: Env<'a>,
    hash_bin: Binary,
    r_bin: Binary,
    s_bin: Binary,
    recovery_id_u8: u8,
) -> Term<'a> {
    if hash_bin.len() != 32 {
        return (atoms::error(), atoms::wrong_hash_size()).encode(env);
    }

    if r_bin.len() != 32 {
        return (atoms::error(), atoms::wrong_r_size()).encode(env);
    }

    if s_bin.len() != 32 {
        return (atoms::error(), atoms::wrong_s_size()).encode(env);
    }

    let mut hash_fixed: [u8; 32] = [0; 32];
    hash_fixed.copy_from_slice(&hash_bin.as_slice()[..32]);
    let message = Message::parse(&hash_fixed);

    let mut s = Scalar::default();

    let mut s_fixed: [u8; 32] = [0; 32];
    s_fixed.copy_from_slice(&s_bin.as_slice()[..32]);
    let _ = s.set_b32(&s_fixed);

    let mut r = Scalar::default();
    let mut r_fixed: [u8; 32] = [0; 32];
    r_fixed.copy_from_slice(&r_bin.as_slice()[..32]);
    let _ = r.set_b32(&r_fixed);

    let signature = Signature { r, s };
    let recovery_id = match RecoveryId::parse(recovery_id_u8) {
        Ok(id) => id,
        Err(_) => return (atoms::error(), atoms::invalid_recovery_id()).encode(env),
    };

    secp256k1_recover(env, message, signature, recovery_id)
}

#[rustler::nif]
fn recover_compact<'a>(
    env: Env<'a>,
    hash_bin: Binary,
    signature_bin: Binary,
    recovery_id_u8: u8,
) -> Term<'a> {
    if hash_bin.len() != 32 {
        return (atoms::error(), atoms::wrong_hash_size()).encode(env);
    }

    if signature_bin.len() != 64 {
        return (atoms::error(), atoms::wrong_signature_size()).encode(env);
    }

    let mut hash_fixed: [u8; 32] = [0; 32];
    hash_fixed.copy_from_slice(&hash_bin.as_slice()[..32]);
    let message = Message::parse(&hash_fixed);

    let mut signature_fixed: [u8; 64] = [0; 64];
    signature_fixed.copy_from_slice(&signature_bin.as_slice()[..64]);
    let signature = Signature::parse(&signature_fixed);

    let recovery_id = match RecoveryId::parse(recovery_id_u8) {
        Ok(id) => id,
        Err(_) => return (atoms::error(), atoms::invalid_recovery_id()).encode(env),
    };

    secp256k1_recover(env, message, signature, recovery_id)
}

#[rustler::nif]
fn create_public_key<'a>(env: Env<'a>, private_key_bin: Binary) -> Term<'a> {
    if private_key_bin.len() != 32 {
        return (atoms::error(), atoms::wrong_private_key_size()).encode(env);
    }

    let mut private_key_fixed: [u8; 32] = [0; 32];
    private_key_fixed.copy_from_slice(&private_key_bin.as_slice()[..32]);
    let private_key = SecretKey::parse(&private_key_fixed).unwrap();

    let public_key = PublicKey::from_secret_key(&private_key);

    let public_key_array = public_key.serialize();
    let mut public_key_result: OwnedBinary = OwnedBinary::new(65).unwrap();
    public_key_result
        .as_mut_slice()
        .copy_from_slice(&public_key_array);

    (atoms::ok(), public_key_result.release(env)).encode(env)
}

fn secp256k1_recover<'a>(
    env: Env<'a>,
    message: Message,
    signature: Signature,
    recovery_id: RecoveryId,
) -> Term<'a> {
    match secp256k1::recover(&message, &signature, &recovery_id) {
        Ok(public_key) => {
            let public_key_array = public_key.serialize();
            let mut public_key_result: OwnedBinary = OwnedBinary::new(65).unwrap();
            public_key_result
                .as_mut_slice()
                .copy_from_slice(&public_key_array);
            (atoms::ok(), public_key_result.release(env)).encode(env)
        }
        Err(_) => (atoms::error(), atoms::recovery_failure()).encode(env),
    }
}

fn secp256k1_sign<'a>(
    env: Env<'a>,
    message_bin: Binary,
    private_key_bin: Binary,
) -> Result<(Signature, RecoveryId), Term<'a>> {
    if message_bin.len() != 32 {
        return Err((atoms::error(), atoms::wrong_message_size()).encode(env));
    }

    if private_key_bin.len() != 32 {
        return Err((atoms::error(), atoms::wrong_private_key_size()).encode(env));
    }

    let mut private_key_fixed: [u8; 32] = [0; 32];
    private_key_fixed.copy_from_slice(&private_key_bin.as_slice()[..32]);

    let mut message_fixed: [u8; 32] = [0; 32];
    message_fixed.copy_from_slice(&message_bin.as_slice()[..32]);

    let private_key = SecretKey::parse(&private_key_fixed).unwrap();
    let message = Message::parse(&message_fixed);

    Ok(secp256k1::sign(&message, &private_key))
}
