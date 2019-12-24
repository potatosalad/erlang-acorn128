%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(acorn128).

%% Public API
-export([crypto_one_time_aead/7]).
%% Internal API
-export([priv_dir/0]).

%%%===================================================================
%%% Public API Functions
%%%===================================================================

crypto_one_time_aead(Cipher, Key, IV, InText, AAD, TagOrTagLength, EncFlag) ->
	acorn128_nif:crypto_one_time_aead(Cipher, Key, IV, InText, AAD, TagOrTagLength, EncFlag).

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
