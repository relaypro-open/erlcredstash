%%% @author Drew Gulino <dgulino@bandwidth.com>
%%% @doc
%%% Erlang implementation of credstash (https://github.com/fugue/credstash)
%%% @end
-module(credstash).

-export([
        new/2, new/4, new/6, 
        delete_secret/2, delete_secret/3,
        get_all_secrets/1, get_all_secrets/2,
        get_secret/2, get_secret/3 ,get_secret/4,
        list_secrets/1, list_secrets/2,
        put_secret/3, put_secret/4, put_secret/5
       ]).

-define(DEFAULT_DDB_TABLE, <<"credential-store">>).
-define(DEFAULT_INITIAL_VERSION, "0000000000000000001").
-define(KMS_KEY, <<"alias/credstash">>).

%%%------------------------------------------------------------------------------
%%% Library initilization
%%%------------------------------------------------------------------------------

default_config() ->
  { erlcloud_aws:default_config(),
    erlcloud_aws:default_config()
  }.

new(AccessKeyID, SecretAccessKey) ->
  KmsConfig = erlcloud_kms:new(AccessKeyID, SecretAccessKey),
  DdbConfig = erlcloud_ddb2:new(AccessKeyID, SecretAccessKey),
  {KmsConfig, DdbConfig}.

new(AccessKeyID, SecretAccessKey, KmsHost, DdbHost) ->
  KmsConfig = erlcloud_kms:new(AccessKeyID, SecretAccessKey, KmsHost),
  DdbConfig = erlcloud_ddb2:new(AccessKeyID, SecretAccessKey, DdbHost),
  {KmsConfig, DdbConfig}.

new(AccessKeyID, SecretAccessKey, KmsHost, DdbHost, KmsPort, DdbPort) ->
  KmsConfig = erlcloud_kms:new(AccessKeyID, SecretAccessKey, KmsHost, KmsPort),
  DdbConfig = erlcloud_ddb2:new(AccessKeyID, SecretAccessKey, DdbHost, DdbPort),
  {KmsConfig, DdbConfig}.


%%%------------------------------------------------------------------------------
%%% delete_secret
%%%------------------------------------------------------------------------------

%%------------------------------------------------------------------------------
%% @doc 
%%
%% ===Example===
%% `
%% credstash:delete_secret(<<"test">>,<<"credential-store">>).
%% '
%% @end
%%------------------------------------------------------------------------------
delete_secret(Name, Table, Config) ->
  {_KmsConfig, DdbConfig} = case Config of
    env -> default_config();
    _ -> Config
  end,           
  {ok, DdbResponse } = erlcloud_ddb2:scan(Table,
                                       [
                                       {filter_expression, <<"#N = :name">>}, 
                                       {expression_attribute_values, [{<<":name">>, Name}]}, 
                                       {projection_expression, <<"#N, version">>},
                                       {expression_attribute_names, [{<<"#N">>, <<"name">>}]}
                                       ],
                                       DdbConfig
                                          ),
  Secrets = DdbResponse,
  DeleteResponse = lists:map(fun(Secret) -> erlcloud_ddb2:delete_item(Table, 
                                             [{<<"name">>,{s, proplists:get_value(<<"name">>,Secret)}},
                                              {<<"version">>,{s, proplists:get_value(<<"version">>,Secret)}}] , 
                                             [{return_values, all_old}], DdbConfig) 
                                            end, Secrets ),
  DeleteResponse.

delete_secret(Name, Config) ->
  Table = ?DEFAULT_DDB_TABLE,
  delete_secret(Name, Table, Config).

%%%------------------------------------------------------------------------------
%%% get_all_secrets
%%%------------------------------------------------------------------------------

%%------------------------------------------------------------------------------
%% @doc 
%%
%% ===Example===
%% `
%% credstash:get_all_secrets(<<"credential-store">>, env).
%% '
%% @end
%%------------------------------------------------------------------------------
get_all_secrets(Table, Config) ->
  {ok,Secrets} = list_secrets(Table, Config),
  Values = lists:map(fun(Secret) -> 
                         Name = proplists:get_value(<<"name">>,Secret),
                         {ok, Value} = get_secret(Name,Table, Config),
                         {Name, Value}
                     end, Secrets),
  {ok, Values}.

get_all_secrets(Config) ->
  Table = ?DEFAULT_DDB_TABLE,
  get_all_secrets(Table, Config).

%%%------------------------------------------------------------------------------
%%% get_secret
%%%------------------------------------------------------------------------------

%%------------------------------------------------------------------------------
%% @doc 
%%
%% ===Example===
%% `
%% credstash:get_secret(<<"test">>,<<"credential-store">>,<<"0000000000000000001">>, env).
%% '
%% @end
%%------------------------------------------------------------------------------
get_secret(Name, Table, Version, Config) ->
  {_KmsConfig, DdbConfig} = case Config of
    env -> default_config();
    _ -> Config
  end,           
  {ok, Ciphertext } = erlcloud_ddb2:get_item(Table, [{<<"name">>,{s,Name}},{<<"version">>,{s, Version}}], DdbConfig),
  decrypt_secret(Ciphertext, Name, Config).

get_secret(Name, Table, Config) ->
  {_KmsConfig, DdbConfig} = case Config of
    env -> default_config();
    _ -> Config
  end,           
  {ok, VersionResponse} = erlcloud_ddb2:q(Table,
                                           <<"#N = :name">>,
                                          [
                                           {expression_attribute_values,
                                              [ {<<":name">>, Name} ]},
                                           {limit, 1},
                                           {consistent_read, true},
                                           {scan_index_forward, false},
                                           {expression_attribute_names, [{<<"#N">>, <<"name">>}]}
                                          ],
                                          DdbConfig
                                        ),
  case VersionResponse of
    [] -> {error, []};
    _ -> 
    {Count,_} = string:to_integer(proplists:get_value(<<"Count">>,VersionResponse)),
    case Count == 0 of
      true -> {error, []};
      false ->
        decrypt_secret(hd(VersionResponse), Name, Config)
    end
  end.

get_secret(Name, Config) ->
  Table = ?DEFAULT_DDB_TABLE,
  get_secret(Name, Table, Config).

%%%------------------------------------------------------------------------------
%%% list_secrets
%%%------------------------------------------------------------------------------

%%------------------------------------------------------------------------------
%% @doc 
%%
%% ===Example===
%% `
%% credstash:list_secrets(<<"credential-store">>, env).
%% '
%% @end
%%------------------------------------------------------------------------------
list_secrets(Table, Config) ->
  {_KmsConfig, DdbConfig} = case Config of
    env -> default_config();
    _ -> Config
  end,           
  DdbResponse = erlcloud_ddb2:scan(Table,
                                       [
                                       {projection_expression, <<"#N, version">>},
                                       {expression_attribute_names, [{<<"#N">>, <<"name">>}]}
                                       ], 
                                       DdbConfig
                                          ),
  DdbResponse. 

list_secrets(Config) ->
  Table = ?DEFAULT_DDB_TABLE,
  list_secrets(Table, Config).

%%%------------------------------------------------------------------------------
%%% put_secret
%%%------------------------------------------------------------------------------

%%------------------------------------------------------------------------------
%% @doc 
%%
%% ===Example===
%% `
%% credstash:put_secret(<<"test">>,<<"best">>,<<"credential-store">>,<<"0000000000000000001">>, env).
%% '
%% @end
%%------------------------------------------------------------------------------
put_secret(Name, Secret, Table, Version, Config) ->
  {KmsConfig, DdbConfig} = case Config of
    env -> default_config();
    _ -> Config
  end,           
  KmsKey = ?KMS_KEY,
  NumberOfBytes=64,
  {ok, KmsResponse} = erlcloud_kms:generate_data_key(KmsKey, [{number_of_bytes, NumberOfBytes},{encryption_context, [{}] } ], KmsConfig),
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
  DdbResponse = erlcloud_ddb2:put_item(Table, Data, [], DdbConfig),
  DdbResponse.

put_secret(Name, Secret, Table, Config) ->
  Version = ?DEFAULT_INITIAL_VERSION,
  put_secret(Name, Secret, Table, Version, Config).

put_secret(Name, Secret, Config) ->
  Table = ?DEFAULT_DDB_TABLE,
  put_secret(Name, Secret, Table, Config).

decrypt_secret(Ciphertext, Name, Config) ->
  {KmsConfig, _DdbConfig} = case Config of
    env -> default_config();
    _ -> Config
  end,           
  KeyBase64 = proplists:get_value(<<"key">>,Ciphertext),
  Hmac = proplists:get_value(<<"hmac">>,Ciphertext),
  Contents = proplists:get_value(<<"contents">>,Ciphertext),
  {ok, KMS_Response} = erlcloud_kms:decrypt(KeyBase64, [], KmsConfig), 
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
