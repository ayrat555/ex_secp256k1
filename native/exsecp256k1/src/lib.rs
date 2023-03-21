use libsecp256k1::curve::Scalar;
use libsecp256k1::Message;
use libsecp256k1::PublicKey;
use libsecp256k1::RecoveryId;
use libsecp256k1::SecretKey;
use libsecp256k1::Signature;
use rustler::Binary;
use rustler::Encoder;
use rustler::Env;
use rustler::NewBinary;
use rustler::Term;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        wrong_message_size,
        wrong_private_key_size,
        wrong_public_key_size,
        wrong_tweak_key_size,
        wrong_signature_size,
        recovery_failure,
        invalid_recovery_id,
        invalid_signature,
        invalid_public_key,
        invalid_private_key,
        invalid_r,
        invalid_s,
        tweak_failure,
        failed_to_verify
    }
}

rustler::init!(
    "Elixir.ExSecp256k1",
    [
        sign,
        sign_compact,
        recover,
        recover_compact,
        create_public_key,
        public_key_tweak_add,
        public_key_tweak_mult,
        public_key_decompress,
        public_key_compress,
        private_key_tweak_add,
        private_key_tweak_mult,
        verify
    ]
);

#[rustler::nif]
fn sign<'a>(env: Env<'a>, message_bin: Binary, private_key_bin: Binary) -> Term<'a> {
    let (Signature { s, r }, recid) = match secp256k1_sign(env, message_bin, private_key_bin) {
        Ok(result) => result,
        Err(error) => return error,
    };

    let mut r_bin = NewBinary::new(env, 32);
    let mut s_bin = NewBinary::new(env, 32);

    r_bin.as_mut_slice().copy_from_slice(&r.b32());
    s_bin.as_mut_slice().copy_from_slice(&s.b32());
    let recid_u8: u8 = recid.into();

    (
        atoms::ok(),
        (Binary::from(r_bin), Binary::from(s_bin), recid_u8),
    )
        .encode(env)
}

#[rustler::nif]
fn sign_compact<'a>(env: Env<'a>, message_bin: Binary, private_key_bin: Binary) -> Term<'a> {
    let (signature, recovery_id) = match secp256k1_sign(env, message_bin, private_key_bin) {
        Ok((result, recovery_id)) => (result.serialize(), recovery_id.serialize()),
        Err(error) => return error,
    };

    let mut signature_bin = NewBinary::new(env, 64);

    signature_bin.as_mut_slice().copy_from_slice(&signature);

    (atoms::ok(), (Binary::from(signature_bin), recovery_id)).encode(env)
}

#[rustler::nif]
fn recover<'a>(
    env: Env<'a>,
    hash_bin: Binary,
    r_bin: Binary,
    s_bin: Binary,
    recovery_id_u8: u8,
) -> Term<'a> {
    let r = match parse_scalar(r_bin) {
        Ok(scalar) => scalar,
        Err(_) => return (atoms::error(), atoms::invalid_r()).encode(env),
    };

    let s = match parse_scalar(s_bin) {
        Ok(scalar) => scalar,
        Err(_) => return (atoms::error(), atoms::invalid_s()).encode(env),
    };

    let message = match parse_message(env, hash_bin) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let recovery_id = match parse_recovery_id(env, recovery_id_u8) {
        Ok(id) => id,
        Err(err) => return err,
    };

    let signature = Signature { r, s };

    secp256k1_recover(env, message, signature, recovery_id)
}

#[rustler::nif]
fn recover_compact<'a>(
    env: Env<'a>,
    hash_bin: Binary,
    signature_bin: Binary,
    recovery_id_u8: u8,
) -> Term<'a> {
    let message = match parse_message(env, hash_bin) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let signature = match parse_signature(env, signature_bin) {
        Ok(sign_result) => sign_result,
        Err(err) => return err,
    };

    let recovery_id = match parse_recovery_id(env, recovery_id_u8) {
        Ok(id) => id,
        Err(err) => return err,
    };

    secp256k1_recover(env, message, signature, recovery_id)
}

#[rustler::nif]
fn create_public_key<'a>(env: Env<'a>, private_key_bin: Binary) -> Term<'a> {
    let private_key = match parse_private_key(env, private_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    let public_key = PublicKey::from_secret_key(&private_key);
    let serialized_public_key = serialize_public_key(env, public_key);

    (atoms::ok(), serialized_public_key).encode(env)
}

#[rustler::nif]
fn public_key_tweak_add<'a>(
    env: Env<'a>,
    public_key_bin: Binary,
    tweak_key_bin: Binary,
) -> Term<'a> {
    let mut public_key = match parse_public_key(env, public_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    let tweak_key = match parse_private_key(env, tweak_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    if let Err(_) = public_key.tweak_add_assign(&tweak_key) {
        return (atoms::error(), atoms::tweak_failure()).encode(env);
    }

    let serialized_public_key = serialize_public_key(env, public_key);
    (atoms::ok(), serialized_public_key).encode(env)
}

#[rustler::nif]
fn public_key_tweak_mult<'a>(
    env: Env<'a>,
    public_key_bin: Binary,
    tweak_key_bin: Binary,
) -> Term<'a> {
    let mut public_key = match parse_public_key(env, public_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    let tweak_key = match parse_private_key(env, tweak_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    if let Err(_) = public_key.tweak_mul_assign(&tweak_key) {
        return (atoms::error(), atoms::tweak_failure()).encode(env);
    }

    let serialized_public_key = serialize_public_key(env, public_key);
    (atoms::ok(), serialized_public_key).encode(env)
}

#[rustler::nif]
fn private_key_tweak_add<'a>(
    env: Env<'a>,
    private_key_bin: Binary,
    tweak_key_bin: Binary,
) -> Term<'a> {
    let mut private_key = match parse_private_key(env, private_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    let tweak_key = match parse_private_key(env, tweak_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    if let Err(_) = private_key.tweak_add_assign(&tweak_key) {
        return (atoms::error(), atoms::tweak_failure()).encode(env);
    }

    let serialized_private_key = serialize_private_key(env, private_key);
    (atoms::ok(), serialized_private_key).encode(env)
}

#[rustler::nif]
fn private_key_tweak_mult<'a>(
    env: Env<'a>,
    private_key_bin: Binary,
    tweak_key_bin: Binary,
) -> Term<'a> {
    let mut private_key = match parse_private_key(env, private_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    let tweak_key = match parse_private_key(env, tweak_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    if let Err(_) = private_key.tweak_mul_assign(&tweak_key) {
        return (atoms::error(), atoms::tweak_failure()).encode(env);
    }

    let serialized_private_key = serialize_private_key(env, private_key);
    (atoms::ok(), serialized_private_key).encode(env)
}

#[rustler::nif]
fn public_key_decompress<'a>(env: Env<'a>, compressed_public_key_bin: Binary) -> Term<'a> {
    if compressed_public_key_bin.len() != 33 {
        return (atoms::error(), atoms::wrong_public_key_size()).encode(env);
    }

    let public_key_slice = compressed_public_key_bin.as_slice();
    let mut public_key_fixed: [u8; 33] = [0; 33];
    public_key_fixed.copy_from_slice(&public_key_slice[0..33]);

    let public_key = match PublicKey::parse_compressed(&public_key_fixed) {
        Ok(key) => key,
        Err(_) => return (atoms::error(), atoms::invalid_public_key()).encode(env),
    };

    let serialized_public_key = serialize_public_key(env, public_key);
    (atoms::ok(), serialized_public_key).encode(env)
}

#[rustler::nif]
fn public_key_compress<'a>(env: Env<'a>, public_key_bin: Binary) -> Term<'a> {
    let public_key = match parse_public_key(env, public_key_bin) {
        Ok(key) => key,
        Err(err) => return err,
    };

    let public_key_array = public_key.serialize_compressed();
    let mut public_key_result = NewBinary::new(env, 33);
    public_key_result
        .as_mut_slice()
        .copy_from_slice(&public_key_array);

    (atoms::ok(), Binary::from(public_key_result)).encode(env)
}

#[rustler::nif]
fn verify<'a>(
    env: Env<'a>,
    message_bin: Binary,
    signature_bin: Binary,
    public_key_bin: Binary,
) -> Term<'a> {
    let message = match parse_message(env, message_bin) {
        Ok(message) => message,
        Err(err) => return err,
    };
    let signature = match parse_signature(env, signature_bin) {
        Ok(signature) => signature,
        Err(err) => return err,
    };

    let public_key = match parse_public_key(env, public_key_bin) {
        Ok(public_key) => public_key,
        Err(err) => return err,
    };

    if libsecp256k1::verify(&message, &signature, &public_key) {
        atoms::ok().encode(env)
    } else {
        (atoms::error(), atoms::failed_to_verify()).encode(env)
    }
}

fn secp256k1_recover<'a>(
    env: Env<'a>,
    message: Message,
    signature: Signature,
    recovery_id: RecoveryId,
) -> Term<'a> {
    match libsecp256k1::recover(&message, &signature, &recovery_id) {
        Ok(public_key) => {
            let serialized_public_key = serialize_public_key(env, public_key);
            (atoms::ok(), serialized_public_key).encode(env)
        }
        Err(_) => (atoms::error(), atoms::recovery_failure()).encode(env),
    }
}

fn secp256k1_sign<'a>(
    env: Env<'a>,
    message_bin: Binary,
    private_key_bin: Binary,
) -> Result<(Signature, RecoveryId), Term<'a>> {
    let message = parse_message(env, message_bin)?;
    let private_key = parse_private_key(env, private_key_bin)?;

    Ok(libsecp256k1::sign(&message, &private_key))
}

fn parse_message<'a>(env: Env<'a>, message_bin: Binary) -> Result<Message, Term<'a>> {
    if message_bin.len() != 32 {
        return Err((atoms::error(), atoms::wrong_message_size()).encode(env));
    }

    let mut message_fixed: [u8; 32] = [0; 32];
    message_fixed.copy_from_slice(&message_bin.as_slice()[..32]);

    let message = Message::parse(&message_fixed);

    Ok(message)
}

fn parse_private_key<'a>(env: Env<'a>, private_key_bin: Binary) -> Result<SecretKey, Term<'a>> {
    if private_key_bin.len() != 32 {
        return Err((atoms::error(), atoms::wrong_private_key_size()).encode(env));
    }

    let mut private_key_fixed: [u8; 32] = [0; 32];
    private_key_fixed.copy_from_slice(&private_key_bin.as_slice()[..32]);

    match SecretKey::parse(&private_key_fixed) {
        Ok(private_key) => Ok(private_key),
        Err(_) => Err((atoms::error(), atoms::invalid_private_key()).encode(env)),
    }
}

fn parse_public_key<'a>(env: Env<'a>, public_key_bin: Binary) -> Result<PublicKey, Term<'a>> {
    if public_key_bin.len() != 65 {
        return Err((atoms::error(), atoms::wrong_public_key_size()).encode(env));
    }

    let public_key_slice = public_key_bin.as_slice();
    let mut public_key_fixed: [u8; 65] = [0; 65];
    public_key_fixed.copy_from_slice(&public_key_slice[0..65]);

    match PublicKey::parse(&public_key_fixed) {
        Ok(key) => Ok(key),
        Err(_) => Err((atoms::error(), atoms::invalid_public_key()).encode(env)),
    }
}

fn parse_signature<'a>(env: Env<'a>, signature_bin: Binary) -> Result<Signature, Term<'a>> {
    if signature_bin.len() != 64 {
        return Err((atoms::error(), atoms::wrong_signature_size()).encode(env));
    }

    let mut signature_fixed: [u8; 64] = [0; 64];
    signature_fixed.copy_from_slice(&signature_bin.as_slice()[..64]);

    match Signature::parse_standard(&signature_fixed) {
        Ok(sign_result) => Ok(sign_result),
        Err(_) => Err((atoms::error(), atoms::invalid_signature()).encode(env)),
    }
}

fn parse_recovery_id<'a>(env: Env<'a>, recovery_id: u8) -> Result<RecoveryId, Term<'a>> {
    match RecoveryId::parse(recovery_id) {
        Ok(id) => Ok(id),
        Err(_) => Err((atoms::error(), atoms::invalid_recovery_id()).encode(env)),
    }
}

fn parse_scalar<'a>(scalar_bin: Binary) -> Result<Scalar, ()> {
    if scalar_bin.len() != 32 {
        return Err(());
    }

    let mut scalar_fixed: [u8; 32] = [0; 32];
    scalar_fixed.copy_from_slice(&scalar_bin.as_slice()[..32]);

    let mut scalar = Scalar::default();
    let overflow: bool = scalar.set_b32(&scalar_fixed).into();

    if overflow {
        return Err(());
    }

    Ok(scalar)
}

fn serialize_public_key<'a>(env: Env<'a>, public_key: PublicKey) -> Binary<'a> {
    let mut erl_bin = NewBinary::new(env, 65);
    let public_key_serialized = public_key.serialize();
    erl_bin
        .as_mut_slice()
        .copy_from_slice(&public_key_serialized);

    erl_bin.into()
}

fn serialize_private_key<'a>(env: Env<'a>, private_key: SecretKey) -> Binary<'a> {
    let mut erl_bin = NewBinary::new(env, 32);
    let private_key_serialized = private_key.serialize();
    erl_bin
        .as_mut_slice()
        .copy_from_slice(&private_key_serialized);

    erl_bin.into()
}
