%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2019, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  24 Dec 2019 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(acorn128_SUITE).

-include_lib("common_test/include/ct.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([acorn128v3_test_vectors/1]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
	case erlang:apply(M, F, A) of
		E ->
			ok;
		T ->
			ct:fail({{M, F, A}, {expected, E}, {got, T}})
	end).

all() ->
	[
		{group, 'acorn128v3'}
	].

groups() ->
	[
		{'acorn128v3', [parallel], [
			acorn128v3_test_vectors
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(acorn128),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(acorn128),
	ok.

init_per_group(G='acorn128v3', Config) ->
	[
		{acorn128v3_test_vectors, [
			{{hexstr2bin("00000000000000000000000000000000"), hexstr2bin("00000000000000000000000000000000"),
				hexstr2bin(""),
				hexstr2bin("")},
				hexstr2bin(""),
				hexstr2bin("835e5317896e86b2447143c74f6ffc1e")},
			{{hexstr2bin("00000000000000000000000000000000"), hexstr2bin("00000000000000000000000000000000"),
				hexstr2bin("01"),
				hexstr2bin("")},
				hexstr2bin("2b"),
				hexstr2bin("4b60640e26f0a99dd01f93bf634997cb")},
			{{hexstr2bin("00000000000000000000000000000000"), hexstr2bin("00000000000000000000000000000000"),
				hexstr2bin(""),
				hexstr2bin("01")},
				hexstr2bin(""),
				hexstr2bin("982ef7d1bba7f89a1575297a095cd7f2")},
			{{hexstr2bin("01000000000000000000000000000000"), hexstr2bin("00000000000000000000000000000000"),
				hexstr2bin("00"),
				hexstr2bin("00")},
				hexstr2bin("e2"),
				hexstr2bin("a986727fe4a8937af0c34d64d653957d")},
			{{hexstr2bin("00000000000000000000000000000000"), hexstr2bin("01000000000000000000000000000000"),
				hexstr2bin("00"),
				hexstr2bin("00")},
				hexstr2bin("c9"),
				hexstr2bin("b25fa0dc4e85e971344ea285a29485d9")},
			{{hexstr2bin("01010101010101010101010101010101"), hexstr2bin("01010101010101010101010101010101"),
				hexstr2bin("01010101010101010101010101010101"),
				hexstr2bin("01010101010101010101010101010101")},
				hexstr2bin("33df5ea576babc5976f2a82096794690"),
				hexstr2bin("528bcaf97eec282a49838e501f5fbd7d")},
			{{hexstr2bin("000102030405060708090a0b0c0d0e0f"), hexstr2bin("000306090c0f1215181b1e2124272a2d"),
				hexstr2bin("01010101010101010101010101010101"),
				hexstr2bin("01010101010101010101010101010101")},
				hexstr2bin("86801fa89e33d99235dd4d1a72ce001a"),
				hexstr2bin("d9c66b4adb3cde073e6350cc7e237e01")},
			{{hexstr2bin("000102030405060708090a0b0c0d0e0f"), hexstr2bin("000306090c0f1215181b1e2124272a2d"),
				hexstr2bin("00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8"),
				hexstr2bin("00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9be")},
				hexstr2bin("e7ef316378444644705c4381c888833b6d62a749005ab8fa146a85904d5e5ab77c57582158395d8fe6b666e6c85177648aeb7784cf2eeaed3c22e7e96bf59009cd7ad21ba5df1a0fc0"),
				hexstr2bin("51b4bd86c68ccf0682f5695d2667d535")},
			{{hexstr2bin("000102030405060708090a0b0c0d0e0f"), hexstr2bin("000306090c0f1215181b1e2124272a2d"),
				hexstr2bin("00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a"),
				hexstr2bin("00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9bec3c8cdd2d7dce1e6ebf0f5faff04090e13181d22272c31363b40454a4f54595e63686d72777c81868b90959a9fa4a9aeb3b8bdc2c7ccd1d6dbe0e5eaeff4f9fe03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3a8adb2b7bcc1c6cbd0d5dadfe4e9eef3f8fd02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5cacfd4d9dee3e8edf2f7fc01060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979ca1a6abb0b5babfc4c9ced3d8dde2e7ecf1f6fb00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9bec3c8cdd2d7dce1e6ebf0f5faff04090e13181d22272c31363b40454a4f54595e63686d72777c81868b90959a9fa4a9aeb3b8bdc2c7ccd1d6dbe0e5eaeff4f9fe03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3a8adb2b7bcc1c6cbd0d5dadfe4e9eef3f8fd02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5cacfd4d9dee3e8edf2f7fc01060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979ca1a6abb0b5babfc4c9ced3d8dde2e7ecf1f6fb0005")},
				hexstr2bin("8277c47229287433692bc694a650649a3fa87ed463e4bf0ed3edcf88ce4d845766ee50d8a61e1300cf9c7ef756194f3ed018fc2d5925cd911f2446723e750c5fcd4324da0f5ecd4d8478bb0c19afc321537a7c4bde0f1dea125db67b166e5e02dd095dddd1374a134ff34897dbfbcc3c471b89436ac9f2c2c6d0531e7df15fb3b3c7d2e512b4de6afd2c1146146e5f29c842ecccd2cf80c1c85ba0596fc06107125798e5fd9df4f194222893d6a575c03b61cedce2be22f8854b2b14b48119c2401462578ce18e5d2c165933aa3fca3a0c96aca5af32ce394d035568bdfabb63662c562756747b588e682eda46fd67363f3c18c43962ca4fff8e4138b7b1930f373f0cdddf1ce71bcd5d2630f196a01cb8fd71a2ef3fb993d55111d17e24eda9e51dab491e7e7b50d500fe9a2a6a95700499c7a17459dc82eaf1adaac39988e62d1b82b3f52046df848d09205242bfbd43825f25873c485a9b41f4d0181696e957ec145371b7833a71ca56eb3f1bf8819870a76623c5efad517937d16898344c20ed309b637da2ce5ab052a8955dc3d19eb35c785d6c4580c5d7c376b1b0ee55a9a6c5c794ebe2f4c7a41a27d5ba7afe4a257c070123d4aa1ada279b2b82ee5340cbc2605f44b7276c4c1434da5e6709ab913b7aca29a0fa4a4d421eb2d4d7ae7d24a666597022794d57faad1f869b177092ee05ea8c8d9b6ce697d852c82e1ea3fab6797e64324df0c0ec475c28a8060eb9aaf153bc5be46134b453277b99c478a482401671075d62f029464e98ca4476fdcef7e219ac6ef4234bfb90eb697498800e61b6d42cb465534f4a4f2f6b39c1736e71902bf5bfd7b1b8f595f73f8c8c1789194550c545f904ec1d9a1b1541a711572ff6a44605ed03ed26bef8b64e29cfcf3e65c12f4c91d9a725eeeff9c01302b5c20c98f65bd4c6218d48f48cb6e9c937c05423b4cc677dccfc33f69dad45ac44d8d988d7779e70e3711a0dd9b978d77d49572b0b895ac8c383a360027e9ce10a574f89277d6f513f6db974270a7bc2d3267e2e87e1f80cf64c8d3f15fbf9d5a579cc39a99f18408485ad46a897404ddab5a2a1905277cfd642528c790f473f4b8f6a9374b8e8d8bcad8050b5eca289ace0c657556b023587af4fd5bf1120f731ebe4ac600639f4ad195ab9df883c8653991bf0a988d79570984d507a4fc32b1a628de951d0e14480e0b4b675962ce66ddcbd69e51056a79e95ae2ffe006fad418803a307fe2a0a97aef8fc50f3d98f924b25012c00f0acf83029c4aed4fc5b580118430a5055426cfc5e7374cb9146c20be368172a66c5dd3c3ca2d057fd36e8704e9499113b16612d6d452fe90ec5c290995fe8ecac535bcbacb6af746b1a864c0fb5e59c8f94c8799bea09bbdf382dfaaee1ec20f119d9f63114ef542fac5f98879643b7ac6abf027d0fdf3b87acc56ad05099"),
				hexstr2bin("c4726bdf67637d3fbd919a33fb9550cb")}
		]}
		| acorn128_ct:start(G, Config)
	].

end_per_group(_Group, Config) ->
	acorn128_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

acorn128v3_test_vectors(Config) ->
	Vectors = ?config(acorn128v3_test_vectors, Config),
	lists:foreach(fun acorn128v3_test_vector/1, Vectors).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
acorn128v3_test_vector({{K, NPub, M, AD}, C, Tag}) ->
	?tv_ok(T0, acorn128, crypto_one_time_aead, [acorn128v3, K, NPub, M, AD, 16, true], {C, Tag}),
	?tv_ok(T1, acorn128, crypto_one_time_aead, [acorn128v3, K, NPub, C, AD, Tag, false], M),
	ok.

%% @private
hexstr2bin(S) ->
	list_to_binary(hexstr2list(S)).

%% @private
hexstr2list([X,Y|T]) ->
	[mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
	[].

%% @private
mkint(C) when $0 =< C, C =< $9 ->
	C - $0;
mkint(C) when $A =< C, C =< $F ->
	C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
	C - $a + 10.
