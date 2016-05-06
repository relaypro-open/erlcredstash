-module(erlcredstash).
-export([start/0]).

-define(APP, erlcredstash).

start() ->
    application:load(?APP),
    {ok, Apps} = application:get_key(?APP, applications),
    [application:start(App) || App <- Apps],
    application:start(?APP).
