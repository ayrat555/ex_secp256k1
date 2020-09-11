use rustler::types::binary::{Binary, OwnedBinary};
use rustler::{Encoder, Env, Term};
use secp256k1::{Message, SecretKey, Signature};

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
    }
}

rustler::rustler_export_nifs! {
    "Elixir.ExSecp256k1",
    [
        ("sign", 2, sign, rustler::SchedulerFlags::DirtyCpu)
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
