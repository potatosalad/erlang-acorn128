# acorn128 NIF

[![Build Status](https://travis-ci.org/potatosalad/erlang-acorn128.svg?branch=master)](https://travis-ci.org/potatosalad/erlang-acorn128) [![Hex.pm](https://img.shields.io/hexpm/v/acorn128.svg)](https://hex.pm/packages/acorn128)

Implementation of ACORN, second choice for use case 1 (Lightweight applications; resource constrained environments) from the [CAESAR competition final portfolio](https://competitions.cr.yp.to/caesar-submissions.html).

See [&ldquo;ACORN: A Lightweight Authenticated Cipher (v3)&rdquo;](https://competitions.cr.yp.to/round3/acornv3.pdf) by [Hongjun Wu](https://www3.ntu.edu.sg/home/wuhj/) for more information.

## Installation

Add `acorn128` to your project's dependencies in `mix.exs`

```elixir
defp deps do
  [
    {:acorn128, "~> 1.0"}
  ]
end
```

Add `acorn128` to your project's dependencies in your `Makefile` for [`erlang.mk`](https://github.com/ninenines/erlang.mk) or the following to your `rebar.config`

```erlang
{deps, [
  {acorn128, ".*", {git, "git://github.com/potatosalad/erlang-acorn128.git", {branch, "master"}}}
]}.
```

## Usage

### Simple API

_Erlang_

```erlang
%% Encryption
Key = crypto:strong_rand_bytes(16), % Key = <<33,126,75,53,220,99,55,188,229,97,154,128,147,91,14,249>>.
IV = crypto:strong_rand_bytes(16),  % IV  = <<60,52,165,219,131,60,192,154,183,168,77,231,240,130,245,118>>.
PlainText = <<"hello, world">>,
AAD = <<"test">>,
{CipherText, CipherTag} = acorn128:encrypt(Key, IV, PlainText, AAD).
% CipherText = <<3,105,56,55,26,140,36,60,63,214,228,107>>.
% CipherTag  = <<28,8,46,253,158,35,196,249,12,174,189,248,160,215,189,10>>.

%% Decryption
PlainText = acorn128:decrypt(Key, IV, CipherText, AAD, CipherTag).
% PlainText = <<"hello, world">>.
```

_Elixir_

```elixir
## Encryption
key = :crypto.strong_rand_bytes(16) # key = <<33,126,75,53,220,99,55,188,229,97,154,128,147,91,14,249>>
iv = :crypto.strong_rand_bytes(16)  # iv  = <<60,52,165,219,131,60,192,154,183,168,77,231,240,130,245,118>>
plaintext = "hello, world"
aad = "test"
{ciphertext, ciphertag} = :acorn128.encrypt(key, iv, plaintext, aad)
# ciphertext = <<3,105,56,55,26,140,36,60,63,214,228,107>>
# ciphertag  = <<28,8,46,253,158,35,196,249,12,174,189,248,160,215,189,10>>

## Decryption
^plaintext = :acorn128.decrypt(key, iv, ciphertext, aad, ciphertag)
# plaintext = "hello, world"
```

### New Crypto API

_Erlang_

```erlang
%% Encryption
Key = crypto:strong_rand_bytes(16), % Key = <<33,126,75,53,220,99,55,188,229,97,154,128,147,91,14,249>>.
IV = crypto:strong_rand_bytes(16),  % IV  = <<60,52,165,219,131,60,192,154,183,168,77,231,240,130,245,118>>.
PlainText = <<"hello, world">>,
AAD = <<"test">>,
{CipherText, CipherTag} = acorn128:crypto_one_time_aead(acorn128v3, Key, IV, PlainText, AAD, true).
% CipherText = <<3,105,56,55,26,140,36,60,63,214,228,107>>.
% CipherTag  = <<28,8,46,253,158,35,196,249,12,174,189,248,160,215,189,10>>.

%% Decryption
PlainText = acorn128:crypto_one_time_aead(acorn128v3, Key, IV, CipherText, AAD, CipherTag, false).
% PlainText = <<"hello, world">>.
```

_Elixir_

```elixir
## Encryption
key = :crypto.strong_rand_bytes(16) # key = <<33,126,75,53,220,99,55,188,229,97,154,128,147,91,14,249>>
iv = :crypto.strong_rand_bytes(16)  # iv  = <<60,52,165,219,131,60,192,154,183,168,77,231,240,130,245,118>>
plaintext = "hello, world"
aad = "test"
{ciphertext, ciphertag} = :acorn128.crypto_one_time_aead(:acorn128v3, key, iv, plaintext, aad, true)
# ciphertext = <<3,105,56,55,26,140,36,60,63,214,228,107>>
# ciphertag  = <<28,8,46,253,158,35,196,249,12,174,189,248,160,215,189,10>>

## Decryption
^plaintext = :acorn128.crypto_one_time_aead(:acorn128v3, key, iv, ciphertext, aad, ciphertag, false)
# plaintext = "hello, world"
```

### SUPERCOP API

_Erlang_

```erlang
%% Encryption
K = crypto:strong_rand_bytes(16),    % K    = <<33,126,75,53,220,99,55,188,229,97,154,128,147,91,14,249>>.
NPub = crypto:strong_rand_bytes(16), % NPub = <<60,52,165,219,131,60,192,154,183,168,77,231,240,130,245,118>>.
M = <<"hello, world">>,
AD = <<"test">>,
C = acorn128:crypto_aead_encrypt(M, AD, NPub, K).
% C = <<3,105,56,55,26,140,36,60,63,214,228,107,28,8,46,253,158,35,196,249,12,174,189,248,160,215,189,10>>.

%% Decryption
M = acorn128:crypto_aead_decrypt(C, AD, NPub, K).
% M = <<"hello, world">>.
```

_Elixir_

```elixir
## Encryption
k = :crypto.strong_rand_bytes(16)    # k    = <<33,126,75,53,220,99,55,188,229,97,154,128,147,91,14,249>>
npub = :crypto.strong_rand_bytes(16) # npub = <<60,52,165,219,131,60,192,154,183,168,77,231,240,130,245,118>>
m = "hello, world"
ad = "test"
c = :acorn128.crypto_aead_encrypt(m, ad, npub, k)
# c = <<3,105,56,55,26,140,36,60,63,214,228,107,28,8,46,253,158,35,196,249,12,174,189,248,160,215,189,10>>

## Decryption
^m = :acorn128.crypto_aead_decrypt(c, ad, npub, k)
# m = "hello, world"
```
