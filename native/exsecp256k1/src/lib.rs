use rustler::types::binary::{Binary, OwnedBinary};
use rustler::{Encoder, Env, Term};
use secp256k1::curve::Scalar;
use secp256k1::{Message, RecoveryId, SecretKey, Signature};

mod atoms {
    rustler::rustler_atoms! {
        atom ok;
        atom error;
        atom message_not_binary;
        atom private_key_not_binary;
        atom hash_not_binary;
        atom r_not_binary;
        atom s_not_binary;
        atom recovery_id_not_u8;
        atom wrong_message_size;
        atom wrong_private_key_size;
        atom wrong_hash_size;
        atom wrong_r_size;
        atom wrong_s_size;
        atom recovery_failure;
        atom invalid_recovery_id;
    }
}

rustler::rustler_export_nifs! {
    "Elixir.ExSecp256k1",
    [
        ("sign", 2, sign, rustler::SchedulerFlags::DirtyCpu),
        ("recover", 4, recover, rustler::SchedulerFlags::DirtyCpu)
    ],
    None
}

fn sign<'a>(env: Env<'a>, args: &[Term<'a>]) -> Term<'a> {
    let message_bin: Binary = match args[0].decode() {
        Ok(binary) => binary,
        Err(_error) => return (atoms::error(), atoms::message_not_binary()).encode(env),
    };

    let private_key_bin: Binary = match args[1].decode() {
        Ok(binary) => binary,
        Err(_error) => return (atoms::error(), atoms::private_key_not_binary()).encode(env),
    };

    if message_bin.len() != 32 {
        return (atoms::error(), atoms::wrong_message_size()).encode(env);
    }

    if private_key_bin.len() != 32 {
        return (atoms::error(), atoms::wrong_private_key_size()).encode(env);
    }

    let mut private_key_fixed: [u8; 32] = [0; 32];
    private_key_fixed.copy_from_slice(&private_key_bin.as_slice()[..32]);

    let mut message_fixed: [u8; 32] = [0; 32];
    message_fixed.copy_from_slice(&message_bin.as_slice()[..32]);

    let private_key = SecretKey::parse(&private_key_fixed).unwrap();
    let message = Message::parse(&message_fixed);

    let (Signature { s, r }, recid) = secp256k1::sign(&message, &private_key);

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

fn recover<'a>(env: Env<'a>, args: &[Term<'a>]) -> Term<'a> {
    let hash_bin: Binary = match args[0].decode() {
        Ok(binary) => binary,
        Err(_error) => return (atoms::error(), atoms::hash_not_binary()).encode(env),
    };

    let r_bin: Binary = match args[1].decode() {
        Ok(binary) => binary,
        Err(_error) => return (atoms::error(), atoms::r_not_binary()).encode(env),
    };

    let s_bin: Binary = match args[2].decode() {
        Ok(binary) => binary,
        Err(_error) => return (atoms::error(), atoms::s_not_binary()).encode(env),
    };

    let recovery_id_u8: u8 = match args[3].decode() {
        Ok(number) => number,
        Err(_error) => return (atoms::error(), atoms::recovery_id_not_u8()).encode(env),
    };

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
