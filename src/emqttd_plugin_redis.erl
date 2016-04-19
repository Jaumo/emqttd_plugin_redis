%%--------------------------------------------------------------------
%% Copyright (c) 2015-2016 Feng Lee <feng@emqtt.io>.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

%% @doc emqttd redis plugin.
-module(emqttd_plugin_redis).

-include("../../../include/emqttd.hrl").

-include("../../../include/emqttd_protocol.hrl").

-export([load/0, unload/0]).

-export([on_client_connected/3]).

-define(APP, ?MODULE).

-define(CLIENT(Username), #mqtt_client{username = Username}).

%% Called when the plugin loaded
load() ->
	lager:error("Init authcmd=~s, clienst_file=~s", [env(authcmd), env(clients_file)]),
    ok = emqttd_access_control:register_mod(
            auth, emqttd_auth_redis, {env(authcmd), env(password_hash), env(clients_file)}),
    with_cmd_enabled(aclcmd, fun(AclCmd) ->
            ok = emqttd_access_control:register_mod(acl, emqttd_acl_redis, {AclCmd, env(acl_nomatch)})
        end),
    with_cmd_enabled(subcmd, fun(SubCmd) ->
            emqttd:hook('client.connected', fun ?MODULE:on_client_connected/3, [SubCmd])
        end).

env(Key) -> {ok, Val} = application:get_env(?APP, Key), Val.

on_client_connected(?CONNACK_ACCEPT, Client = #mqtt_client{username = undefined}, _LoadCmd) ->
    {ok, Client};

on_client_connected(?CONNACK_ACCEPT, Client = #mqtt_client{username   = Username,
                                                           client_pid = ClientPid}, LoadCmd) ->
    CmdList = repl_var(LoadCmd, Username),
    case emqttd_redis_client:query(CmdList) of
        {ok, Values}   -> emqttd_client:subscribe(ClientPid, topics(Values));
        {error, Error} -> lager:error("Redis Error: ~p, Cmd: ~p", [Error, CmdList])
    end,
    {ok, Client};

on_client_connected(_ConnAck, _Client, _LoadCmd) ->
    ok.

unload() ->
    emqttd:unhook('client.connected', fun ?MODULE:on_client_connected/3),
    emqttd_access_control:unregister_mod(auth, emqttd_auth_redis),
    with_cmd_enabled(aclcmd, fun(_AclCmd) ->
            emqttd_access_control:unregister_mod(acl, emqttd_acl_redis)
        end).

with_cmd_enabled(Name, Fun) ->
    case application:get_env(emqttd_plugin_redis, Name) of
        {ok, Cmd}  -> Fun(Cmd);
        undefined  -> ok
    end.

repl_var(Cmd, Username) ->
    [re:replace(S, "%u", Username, [{return, binary}]) || S <- Cmd].

topics(Values) ->
    topics(Values, []).
topics([], Acc) ->
    Acc;
topics([Topic, Qos | Vals], Acc) ->
    topics(Vals, [{Topic, i(Qos)}|Acc]).

i(S) -> list_to_integer(binary_to_list(S)).

