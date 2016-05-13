-module(credstash).

-export([
        get_secret/1, get_secret/2,
        put_secret/2,put_secret/3,
        list_secrets/0, list_secrets/1,
        get_all_secrets/0, get_all_secrets/1,
        delete_secret/1, delete_secret/2
       ]).

-define(DEFAULT_DDB_TABLE, <<"credential-store">>).

get_secret(Name, Table) ->
  {ok, Ciphertext } = erlcloud_ddb:get_item(Table, {Name, "0000000000000000001"}),
  KeyBase64 = proplists:get_value(<<"key">>,Ciphertext),
  Hmac = proplists:get_value(<<"hmac">>,Ciphertext),
  Contents = proplists:get_value(<<"contents">>,Ciphertext),
  {ok, KMS_Response} = erlcloud_kms:decrypt(KeyBase64), 
  KeyId = proplists:get_value(<<"KeyId">>,KMS_Response),
  Plaintext = base64:decode(proplists:get_value(<<"Plaintext">>,KMS_Response)),
  Key=binary:part(Plaintext, 0, 32),
  HmacKey=binary:part(Plaintext, 32, byte_size(Plaintext) - byte_size(Key)),
  DecodedContents = base64:decode(Contents),
  Digest = crypto:hmac(sha256, HmacKey, DecodedContents ),
  HexDigest = hexlify(Digest),
  Ivec = <<1:128>>,
  State = crypto:stream_init(aes_ctr, Key, Ivec),
  {_NewState, Text} = crypto:stream_decrypt(State, DecodedContents),
  {ok, Text}.

get_secret(Name) ->
  Table = ?DEFAULT_DDB_TABLE,
  get_secret(Name, Table).


hexlify(Bin) when is_binary(Bin) ->
    << <<(hex(H)),(hex(L))>> || <<H:4,L:4>> <= Bin >>.

hex(C) when C < 10 -> $0 + C;
hex(C) -> $a + C - 10.

put_secret(Name, Secret, Table) ->
  KmsKey = <<"alias/credstash">>,
  NumberOfBytes=64,
  {ok, KmsResponse} = erlcloud_kms:generate_data_key(KmsKey, [{number_of_bytes, NumberOfBytes},{encryption_context, [{}] } ]),
  CiphertextBlob = proplists:get_value(<<"CiphertextBlob">>,KmsResponse),
  Plaintext = base64:decode(proplists:get_value(<<"Plaintext">>,KmsResponse)),
  KeyId = proplists:get_value(<<"KeyId">>,KmsResponse),
  DataKey=binary:part(Plaintext, 0, 32),
  HmacKey=binary:part(Plaintext, 32, byte_size(Plaintext) - byte_size(DataKey)),
  WrappedKey = CiphertextBlob,
  Ivec = <<1:128>>,
  State = crypto:stream_init(aes_ctr, DataKey, Ivec),
  {_NewState, CText} = crypto:stream_encrypt(State, Secret),
  DecodedCText = base64:encode(CText),
  Hmac = crypto:hmac(sha256, HmacKey, CText),
  B64Hmac = hexlify(Hmac),
  Version = <<"0000000000000000001">>,
  Data = [{<<"name">>, Name},
          {<<"version">>, Version},
          {<<"key">>, WrappedKey},
          {<<"contents">>, base64:encode(CText)},
          {<<"hmac">>, B64Hmac}],
  DdbResponse = erlcloud_ddb:put_item(Table, Data),
  DdbResponse.
  

put_secret(Name, Secret) ->
  Table = ?DEFAULT_DDB_TABLE,
  put_secret(Name, Secret, Table).

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
