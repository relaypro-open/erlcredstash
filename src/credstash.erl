-module(credstash).

-export([
        get_secret/1, get_secret/2,
				encode16/1, hexlify/1
        %%put_secret/2,put_secret/3
       ]).
-define(KMS_KEY_ALGO, "AES-256").

get_secret(Name, Table) ->
  {ok, Ciphertext } = erlcloud_ddb:get_item(Table, {Name, "0000000000000000001"}),
  io:format("Ciphertext: ~p~n",[Ciphertext]),
  io:format("Ciphertext keys: ~p~n",[proplists:get_keys(Ciphertext)]),
  KeyBase64 = proplists:get_value(<<"key">>,Ciphertext),
  io:format("KeyBase64: ~p~n",[KeyBase64]),
  %%Key = base64:decode(KeyBase64),
  %%io:format("Key: ~p~n",[Key]),
  Hmac = proplists:get_value(<<"hmac">>,Ciphertext),
  Contents = proplists:get_value(<<"contents">>,Ciphertext),
  io:format("Contents: ~p~n",[Contents]),
  %%Plaintext = erlcloud_ddb:get_item(Table, <<"name">>e},
  %%                                 [consistent_read,
  %%                                  {attributes_to_get, [<<"contents">>]}]),
  {ok, KMS_Response} = erlcloud_kms:decrypt(KeyBase64), 
  io:format("KMS_Response: ~p~n",[KMS_Response]),
  KeyId = proplists:get_value(<<"KeyId">>,KMS_Response),
  Plaintext = base64:decode(proplists:get_value(<<"Plaintext">>,KMS_Response)),
  %Key = lists:sublist(Plaintext, 1, 32),
  %HmacKey = lists:sublist(Plaintext, 33, 32),
  %%Key=list:sublistPlaintext, 0, 32),
  Key=binary:part(Plaintext, 0, 32),
  io:format("Plaintext: ~w~n",[Plaintext]),
  %%io:format("base64:decode Plaintext: ~w~n",[base64:decode(Plaintext)]),
  io:format("Key: ~w~n",[Key]),
  HmacKey=binary:part(Plaintext, 32, byte_size(Plaintext) - byte_size(Key)),
  io:format("HmacKey: ~w~n",[HmacKey]),
  %%<<X:256/big-unsigned-integer>> = crypto:hash(sha256,"somenewstring"),
  %%ComputedHmac = lists:flatten(io_lib:format("~64.16.0b", [X])),
  %%ComputedHmac = crypto:hmac(sha256, HmacKey, base64:decode(Contents)),
  DecodedContents = base64:decode(Contents),
  io:format("Contents: ~w~n",[base64:decode(Contents)]),
  %io:format("DecodedContents: ~p~n",[DecodedContents]),
  Digest = crypto:hmac(sha256, HmacKey, DecodedContents ),
  io:format("Digest: ~p~n",[Digest]),
  HexDigest = hexlify(Digest),
  io:format("HexDigest: ~p~n",[HexDigest]),
  %% compare HMACs
  IvLen = 16,
  Ivec = crypto:strong_rand_bytes(IvLen),
  %%io:format("Ivec: ~w~n",[Ivec]),
  %%<<Ivec:16, Ciphertext/binary>> = DecodedContents
  State = crypto:stream_init(aes_ctr, Key, Ivec),
  UnencryptedText = crypto:stream_decrypt(State, DecodedContents),
  UnencryptedText.

  %%<<X:256/integer>> = crypto:hmac(sha256, Key, base64:decode(Contents)),
  %%ComputedHmac = lists:flatten(io_lib:format("~64.16.0b", [X])),
  %%ComputedHmac = X, 
  %%<<ComputedHmac:256/integer>> = crypto:hmac(sha256, Key, Contents),
  %%ComputedHmac = crypto:hmac(sha256, Key, base64:decode(Contents)),
  %%io:format("Computed HMac: ~p~n",[ComputedHmac]),
  %%io:format("KMS_Response: ~p~n",[KMS_Response]),
  %%HmacHex = encode16(ComputedHmac),
  %%io:format("HmacHex: ~p~n",[HmacHex]).
  %%io:format("Key: ~p~n",[Key]),
  %%Plaintext = erlcloud_kms:decrypt(Key,[]),
  %%  {ok, [{_,KeyId},{_,PlaintextdePlaintext = base64:decode(Plainbase64),
  %%io:format("Plaintext: ~p~n",[Plaintext]).

get_secret(Name) ->
  Table = <<"credential-store">>,
  get_secret(Name, Table).

encode16(Binary) ->
  << << if N >= 10 -> N -10 + $a;
  true    -> N     + $0 end >>
  || <<N:4>> <= crypto:hash(sha256, Binary) >>.

hexlify(Bin) when is_binary(Bin) ->
    << <<(hex(H)),(hex(L))>> || <<H:4,L:4>> <= Bin >>.

hex(C) when C < 10 -> $0 + C;
hex(C) -> $a + C - 10.

%%put_secret(Name, Value, Table) ->
%%  KeyId=list_to_binary("alias/credstash"),
%%  NumberOfBytes=64,
%%  KmsResponse = erlcloud_kms:generate_data_key(KeyId, [{number_of_bytes, NumberOfBytes}]),
%%  io:format("KmsResponse: ~p~n",[KmsResponse]),
%%  {ok, [{<<"CiphertextBlob">>,CiphertextBlob},
%%        {<<"KeyId">>,KeyId},
%%        {<<"Plaintext">>,Plaintext}]} = KmsResponse,
%%  DataKey = lists:sublist(Plaintext, 1, 32),
%%  HmacKey = lists:sublist(Plaintext, 33, 32),
%%  WrappedKey = CiphertextBlob,
%%  %%Key = crypto:rand_bytes(16),
%%  %%IV = crypto:rand_bytes(16),
%%  EncryptedContent = crypto:block_encrypt(aes_ctr, DataKey, HmacKey, Value),
%%  EncryptedKey = public_key:encrypt_private(list_to_binary([DataKey, HmacKey]), PrivKey),
%%  CText = [integer_to_binary(byte_size(EncryptedKey)), EncryptedKey, EncryptedContent],
%%  %%EncCtr = Counter.new(128),
%%  %%Encrypter = AES(DataKey, AES.MODE_CTR, counter=EncCtr),
%%  %%CText = erlcloud_kms:encrypt(Value),
%%  %%block_encrypt(Type, Key, Ivec, PlainText) -> CipherText
%%  %%CText = crypto:aes_cfb_128_encrypt(DataKey, IV, Value),
%%  %%Hmac = HMAC(HmacKey, msg=CText, digestmode=SHA256),
%%  Hmac = crypto:hmac(sha256, HmacKey, CText),
%%  %%B64HMac = Hmac.hexdigits(),
%%  B64Hmac = encode16(Hmac),
%%  io:format("EncryptedKey: ~p~n",[EncryptedKey]),
%%  Data = [{"name", Name},
%%          {"version", ""},
%%          {"key", base64:encode(WrappedKey)},
%%          {"contents", base64:encode(CText)},
%%          {"hmac", B64Hmac}],
%%  Data.
%%
%%
%%put_secret(Name, Value) ->
%%  Table = <<"credential-store">>,
%%  put_secret(Name, Value, Table).
