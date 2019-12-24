%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(acorn128).

%% Simple API
-export([encrypt/4]).
-export([decrypt/5]).
%% New Crypto API
-export([crypto_one_time_aead/6]).
-export([crypto_one_time_aead/7]).
%% SUPERCOP API
-export([crypto_aead_encrypt/4]).
-export([crypto_aead_decrypt/4]).
%% Internal API
-export([priv_dir/0]).

%%%===================================================================
%%% Simple API Functions
%%%===================================================================

encrypt(Key, IV, PlainText, AAD) ->
	crypto_one_time_aead(acorn128v3, Key, IV, PlainText, AAD, true).

decrypt(Key, IV, CipherText, AAD, CipherTag) ->
	crypto_one_time_aead(acorn128v3, Key, IV, CipherText, AAD, CipherTag, false).

%%%===================================================================
%%% New Crypto API Functions
%%%===================================================================

crypto_one_time_aead(Cipher, Key, IV, InText, AAD, EncFlag) ->
	crypto_one_time_aead(Cipher, Key, IV, InText, AAD, 16, EncFlag).

crypto_one_time_aead(Cipher, Key, IV, InText, AAD, TagOrTagLength, EncFlag) ->
	acorn128_nif:crypto_one_time_aead(Cipher, Key, IV, InText, AAD, TagOrTagLength, EncFlag).

%%%===================================================================
%%% SUPERCOP API Functions
%%%===================================================================

crypto_aead_encrypt(M, AD, NPub, K) ->
	{CipherText, CipherTag} = encrypt(K, NPub, M, AD),
	<<CipherText/binary, CipherTag/binary>>.

crypto_aead_decrypt(C, AD, NPub, K) ->
	case byte_size(C) of
		CipherTextLen0 when CipherTextLen0 >= 16 ->
			CipherTextLen = CipherTextLen0 - 16,
			<<CipherText:CipherTextLen/binary, CipherTag/binary>> = C,
			decrypt(K, NPub, CipherText, AD, CipherTag);
		_ ->
			error
	end.

%%%===================================================================
%%% Internal API Functions
%%%===================================================================

-spec priv_dir() -> file:filename_all().
priv_dir() ->
	case code:priv_dir(?MODULE) of
		{error, bad_name} ->
			case code:which(?MODULE) of
				Filename when is_list(Filename) ->
					filename:join([filename:dirname(Filename), "../priv"]);
				_ ->
					"../priv"
			end;
		Dir ->
			Dir
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
