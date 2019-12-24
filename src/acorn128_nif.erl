%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(acorn128_nif).

%% NIF Functions
-export([crypto_one_time_aead/7]).

-on_load(init/0).

%%%===================================================================
%%% NIF Functions
%%%===================================================================

crypto_one_time_aead(_Cipher, _Key, _IV, _InText, _AAD, _TagOrTagLength, _EncFlag) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
init() ->
	SoName = filename:join(acorn128:priv_dir(), ?MODULE_STRING),
	erlang:load_nif(SoName, 0).
