# ErlCredStash: CredStash For Erlang #

ErlCredStash is an Erlang implementation of CredStash (Python : https://github.com/fugue/credstash). CredStash is a very simple, easy to use credential management and distribution system that uses AWS Key Management Service (KMS) for key wrapping and master-key storage, and DynamoDB for credential storage and sharing.  

## Getting started ##
You need to clone the repository and download rebar (if it's not already available in your path).

```
git clone https://github.com/Phonebooth/erlcredstash.git
cd erlcredstash
wget http://cloud.github.com/downloads/basho/rebar/rebar && chmod u+x rebar
```


To compile and run ErlCredStash
```
make
make run
```

If you're using ErlCredStash in your application, add it as a dependency in your application's configuration file.  To use ErlCredStash in the shell, you can start it by calling:

```
ssl:start().
erlcloud:start().
```

You can either either either either either either either either provide your amazon credentials in environmental variables.

```
export AWS_ACCESS_KEY_ID=<Your AWS Access Key>
export AWS_SECRET_ACCESS_KEY=<Your AWS Secret Access Key>
```
if you want to use ENV variables pass the atom 'env' as the Config
```
credstash:put_secret(<<"test">>,<<"xest">>, env).
```
or specicy the config in each function:
```
Config = credstash:new("$AWS_ACCESS_KEY_ID","$AWS_ACCESS_KEY_ID").
```

Then you can start making api calls, like:

```
credstash:put_secret(<<"test">>,<<"xest">>, Config).
credstash:get_secret(<<"test">>,<<"credential-store">>,<<"0000000000000000001">>, Config).
credstash:put_secret(<<"test">>,<<"best">>,<<"credential-store">>,<<"0000000000000000002">>, Config).
credstash:get_secret(<<"test">>,<<"credential-store">>,<<"0000000000000000002">>, Config).
credstash:list_secrets(Config).
credstash:list_secrets(<<"credential-store">>, Config).
credstash:get_all_secrets(Config).
credstash:get_all_secrets(<<"credential-store">>, Config).
credstash:delete_secret(<<"test">>,<<"credential-store">>, Config).
```

TODO:
```
credstash:setup(<<"table_name">>)
#For now, use the python implementation to setup credstash ddb tables.
```

Elixir iex:
```
$ ./iex.sh
iex(1)> :ssl.start()
:ok
iex(2)> :erlcloud.start()
:ok
iex(3)> :credstash.get_secret("zest")
{:ok, "zest"}
```
