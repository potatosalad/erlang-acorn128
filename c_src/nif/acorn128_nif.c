// -*- mode: c++; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c++ et

#include "acorn128_nif.h"
#include "api.h"
#include "crypto_one_time_aead.h"

static ERL_NIF_TERM ATOM_acorn128v3;
static ERL_NIF_TERM ATOM_badarg;
static ERL_NIF_TERM ATOM_error;
static ERL_NIF_TERM ATOM_false;
static ERL_NIF_TERM ATOM_notsup;
static ERL_NIF_TERM ATOM_true;

/* All nif functions return a valid value or throws an exception */
#define EXCP(Env, Id, Str)                                                                                                         \
    enif_raise_exception((Env), enif_make_tuple3((Env), (Id),                                                                      \
                                                 enif_make_tuple2((Env), enif_make_string((Env), __FILE__, (ERL_NIF_LATIN1)),      \
                                                                  enif_make_int((Env), __LINE__)),                                 \
                                                 enif_make_string((Env), (Str), (ERL_NIF_LATIN1))))

#define EXCP_NOTSUP(Env, Str) EXCP((Env), ATOM_notsup, (Str))
#define EXCP_BADARG(Env, Str) EXCP((Env), ATOM_badarg, (Str))
#define EXCP_ERROR(Env, Str) EXCP((Env), ATOM_error, (Str))

/* NIF Function Declarations */

static ERL_NIF_TERM acorn128_nif_crypto_one_time_aead_7(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

/* NIF Function Definitions */

/* acorn128_nif:crypto_one_time_aead/7 */

static ERL_NIF_TERM
acorn128_nif_crypto_one_time_aead_7(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int encflag;
    unsigned int tag_len;
    ErlNifBinary k;
    ErlNifBinary npub;
    ErlNifBinary in_text;
    ErlNifBinary ad;
    ErlNifBinary tag;
    ERL_NIF_TERM out_term;
    ERL_NIF_TERM tag_term;
    unsigned char *out = NULL;
    if (argc != 7) {
        return EXCP_NOTSUP(env, "argc must be 7");
    }
    /* Fetch the flag telling if we are going to encrypt (=true) or decrypt (=false) */
    if (argv[6] == ATOM_true) {
        encflag = 1;
    } else if (argv[6] == ATOM_false) {
        encflag = 0;
    } else {
        return EXCP_BADARG(env, "Bad EncFlag");
    }
    if (!enif_is_atom(env, argv[0])) {
        return EXCP_BADARG(env, "non-atom Cipher");
    }
    if (argv[0] != ATOM_acorn128v3) {
        return EXCP_NOTSUP(env, "Unsupported Cipher");
    }
    if (!enif_inspect_iolist_as_binary(env, argv[1], &k)) {
        return EXCP_BADARG(env, "non-binary Key");
    }
    if (k.size != CRYPTO_KEYBYTES) {
        return EXCP_BADARG(env, "Bad Key size");
    }
    if (!enif_inspect_iolist_as_binary(env, argv[2], &npub)) {
        return EXCP_BADARG(env, "non-binary IV");
    }
    if (npub.size != CRYPTO_NPUBBYTES) {
        return EXCP_BADARG(env, "Bad IV size");
    }
    if (!enif_inspect_iolist_as_binary(env, argv[3], &in_text)) {
        return EXCP_BADARG(env, "non-binary InText");
    }
    if (!enif_inspect_iolist_as_binary(env, argv[4], &ad)) {
        return EXCP_BADARG(env, "non-binary AAD");
    }
    if (encflag) {
        if (!enif_get_uint(env, argv[5], &tag_len)) {
            return EXCP_BADARG(env, "non-integer TagLength");
        }
        if (tag_len != CRYPTO_ABYTES) {
            return EXCP_BADARG(env, "Bad TagLength");
        }
        out = enif_make_new_binary(env, in_text.size, &out_term);
        if (out == NULL) {
            return EXCP_ERROR(env, "Can't allocate 'OutCryptoText' binary");
        }
        tag.data = enif_make_new_binary(env, CRYPTO_ABYTES, &tag_term);
        if (tag.data == NULL) {
            return EXCP_ERROR(env, "Can't allocate 'OutTag' binary");
        }
        (void)acorn128v3_crypto_one_time_aead_encrypt(out, tag.data, in_text.data, in_text.size, ad.data, ad.size, npub.data,
                                                      k.data);
        return enif_make_tuple2(env, out_term, tag_term);
    } else {
        if (!enif_inspect_iolist_as_binary(env, argv[5], &tag)) {
            return EXCP_BADARG(env, "non-binary Tag");
        }
        if (tag.size != CRYPTO_ABYTES) {
            return EXCP_BADARG(env, "Bad Tag size");
        }
        out = enif_make_new_binary(env, in_text.size, &out_term);
        if (out == NULL) {
            return EXCP_ERROR(env, "Can't allocate 'OutPlainText' binary");
        }
        if (acorn128v3_crypto_one_time_aead_decrypt(out, in_text.data, in_text.size, tag.data, ad.data, ad.size, npub.data,
                                                    k.data) == 0) {
            return out_term;
        } else {
            return ATOM_error;
        }
    }
}

/* NIF Callbacks */

static ErlNifFunc acorn128_nif_funcs[] = {
    {"crypto_one_time_aead", 7, acorn128_nif_crypto_one_time_aead_7, ERL_NIF_DIRTY_JOB_CPU_BOUND}};

static void acorn128_nif_make_atoms(ErlNifEnv *env);
static int acorn128_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
static int acorn128_nif_upgrade(ErlNifEnv *env, void **new_priv_data, void **old_priv_data, ERL_NIF_TERM load_info);
static void acorn128_nif_unload(ErlNifEnv *env, void *priv_data);

static void
acorn128_nif_make_atoms(ErlNifEnv *env)
{
#define ATOM(Id, Value)                                                                                                            \
    {                                                                                                                              \
        Id = enif_make_atom(env, Value);                                                                                           \
    }
    ATOM(ATOM_acorn128v3, "acorn128v3");
    ATOM(ATOM_badarg, "badarg");
    ATOM(ATOM_error, "error");
    ATOM(ATOM_false, "false");
    ATOM(ATOM_notsup, "notsup");
    ATOM(ATOM_true, "true");
#undef ATOM
}

static int
acorn128_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    int retval = 0;

    // Unused
    (void)priv_data;
    (void)load_info;

    /* Initialize common atoms */
    (void)acorn128_nif_make_atoms(env);

    return retval;
}

static int
acorn128_nif_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
    int retval = 0;

    // Unused
    (void)priv_data;
    (void)old_priv_data;
    (void)load_info;

    /* Initialize common atoms */
    (void)acorn128_nif_make_atoms(env);

    return retval;
}

static void
acorn128_nif_unload(ErlNifEnv *env, void *priv_data)
{
    // Unused
    (void)env;
    (void)priv_data;
    return;
}

ERL_NIF_INIT(acorn128_nif, acorn128_nif_funcs, acorn128_nif_load, NULL, acorn128_nif_upgrade, acorn128_nif_unload)
