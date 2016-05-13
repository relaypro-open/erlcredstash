-module(credstash).
-author('dgulino@bandwidth.com').

-export([
        delete_secret/1, delete_secret/2,
        get_all_secrets/0, get_all_secrets/1,
        get_secret/1, get_secret/2,get_secret/3,
        list_secrets/0, list_secrets/1,
        put_secret/2,put_secret/3,put_secret/4
       ]).

-define(DEFAULT_DDB_TABLE, <<"credential-store">>).
-define(DEFAULT_INITIAL_VERSION, "0000000000000000001").
-define(KMS_KEY, <<"alias/credstash">>).

delete_secret(Name, Table) ->
  {ok, DdbResponse } = erlcloud_ddb2:scan(Table,
                                       [
                                       {filter_expression, <<"#N = :name">>}, 
                                       {expression_attribute_values, [{<<":name">>, Name}]}, 
                                       {projection_expression, <<"#N, version">>},
                                       {expression_attribute_names, [{<<"#N">>, <<"name">>}]}
                                       ]
                                          ),
  io:format("DdbResponse: ~p~n", [DdbResponse]),
  Secrets = DdbResponse,
  io:format("Secrets: ~p~n", [Secrets]),
  DeleteResponse = lists:map(fun(Secret) -> erlcloud_ddb2:delete_item(Table, 
                                             [{<<"name">>,{s, proplists:get_value(<<"name">>,Secret)}},
                                              {<<"version">>,{s, proplists:get_value(<<"version">>,Secret)}}] , 
                                             [{return_values, all_old}]) 
                                            end, Secrets ),
  DeleteResponse.

delete_secret(Name) ->
  Table = ?DEFAULT_DDB_TABLE,
  delete_secret(Name, Table).

get_all_secrets(Table) ->
  {ok,Secrets} = list_secrets(Table),
  Values = lists:map(fun(Secret) -> 
                         Name = proplists:get_value(<<"name">>,Secret),
                         {ok, Value} = get_secret(Name,Table),
                         {Name, Value}
                     end, Secrets),
  {ok, Values}.

get_all_secrets() ->
  Table = ?DEFAULT_DDB_TABLE,
  get_all_secrets(Table).

get_secret(Name, Table, Version) ->
  {ok, Ciphertext } = erlcloud_ddb2:get_item(Table, [{<<"name">>,{s,Name}},{<<"version">>,{s, Version}}]),
  decrypt_secret(Ciphertext, Name).

get_secret(Name, Table) ->
  {ok, VersionResponse} = erlcloud_ddb2:q(Table,
                                           <<"#N = :name">>,
                                          [
                                           {expression_attribute_values,
                                              [ {<<":name">>, Name} ]},
                                           {limit, 1},
                                           {consistent_read, true},
                                           {scan_index_forward, false},
                                           {expression_attribute_names, [{<<"#N">>, <<"name">>}]}
                                          ]
                                        ),
  io:format("VersionResponse: ~p~n", [VersionResponse]),
  Count = proplists:get_value(<<"Count">>,VersionResponse),
  case Count == 0 of
    true -> {error, "Not Found"};
    false ->
      decrypt_secret(hd(VersionResponse), Name)
  end.

get_secret(Name) ->
  Table = ?DEFAULT_DDB_TABLE,
  get_secret(Name, Table).

list_secrets(Table) ->
  DdbResponse = erlcloud_ddb2:scan(Table,
                                       [
                                       {projection_expression, <<"#N, version">>},
                                       {expression_attribute_names, [{<<"#N">>, <<"name">>}]}
                                       ]
                                          ),
  DdbResponse. 

list_secrets() ->
  Table = ?DEFAULT_DDB_TABLE,
  list_secrets(Table).

put_secret(Name, Secret, Table, Version) ->
  KmsKey = ?KMS_KEY,
  NumberOfBytes=64,
  {ok, KmsResponse} = erlcloud_kms:generate_data_key(KmsKey, [{number_of_bytes, NumberOfBytes},{encryption_context, [{}] } ]),
  CiphertextBlob = proplists:get_value(<<"CiphertextBlob">>,KmsResponse),
  Plaintext = base64:decode(proplists:get_value(<<"Plaintext">>,KmsResponse)),
  DataKey=binary:part(Plaintext, 0, 32),
  HmacKey=binary:part(Plaintext, 32, byte_size(Plaintext) - byte_size(DataKey)),
  WrappedKey = CiphertextBlob,
  Ivec = <<1:128>>,
  State = crypto:stream_init(aes_ctr, DataKey, Ivec),
  {_NewState, CText} = crypto:stream_encrypt(State, Secret),
  Hmac = crypto:hmac(sha256, HmacKey, CText),
  B64Hmac = hexlify(Hmac),
  Data = [{<<"name">>, Name},
          {<<"version">>, Version},
          {<<"key">>, WrappedKey},
          {<<"contents">>, base64:encode(CText)},
          {<<"hmac">>, B64Hmac}],
  DdbResponse = erlcloud_ddb2:put_item(Table, Data),
  DdbResponse.

put_secret(Name, Secret, Table) ->
  Version = ?DEFAULT_INITIAL_VERSION,
  put_secret(Name, Secret, Table, Version).

put_secret(Name, Secret) ->
  Table = ?DEFAULT_DDB_TABLE,
  put_secret(Name, Secret, Table).

decrypt_secret(Ciphertext, Name) ->
  KeyBase64 = proplists:get_value(<<"key">>,Ciphertext),
  Hmac = proplists:get_value(<<"hmac">>,Ciphertext),
  Contents = proplists:get_value(<<"contents">>,Ciphertext),
  {ok, KMS_Response} = erlcloud_kms:decrypt(KeyBase64), 
  Plaintext = base64:decode(proplists:get_value(<<"Plaintext">>,KMS_Response)),
  Key=binary:part(Plaintext, 0, 32),
  HmacKey=binary:part(Plaintext, 32, byte_size(Plaintext) - byte_size(Key)),
  DecodedContents = base64:decode(Contents),
  Digest = crypto:hmac(sha256, HmacKey, DecodedContents ),
  HexDigest = hexlify(Digest),
  case Hmac == HexDigest of
    false ->
      {error, io_lib:format("Computed HMAC on ~s does not match stored HMAC", [Name])};
    true ->
      Ivec = <<1:128>>,
      State = crypto:stream_init(aes_ctr, Key, Ivec),
      {_NewState, Text} = crypto:stream_decrypt(State, DecodedContents),
      {ok, Text}
  end.    

hexlify(Bin) when is_binary(Bin) ->
    << <<(hex(H)),(hex(L))>> || <<H:4,L:4>> <= Bin >>.

hex(C) when C < 10 -> $0 + C;
hex(C) -> $a + C - 10.
