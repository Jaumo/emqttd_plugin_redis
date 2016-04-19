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

%% @doc Authentication with Redis.
-module(emqttd_auth_redis).

-behaviour(emqttd_auth_mod).

-include("../../../include/emqttd.hrl").

-export([init/1, check/3, description/0]).

-record(state, {auth_cmd, hash_type}).

-define(AUTH_CLIENTID_TAB, mqtt_auth_clientid).

-record(?AUTH_CLIENTID_TAB, {client_id, ipaddr, password}).

-define(UNDEFINED(S), (S =:= undefined orelse S =:= <<>>)).

init({AuthCmd, HashType, ClientsFile}) ->
    mnesia:create_table(?AUTH_CLIENTID_TAB, [
            {ram_copies, [node()]},
            {attributes, record_info(fields, ?AUTH_CLIENTID_TAB)}]),
    mnesia:add_table_copy(?AUTH_CLIENTID_TAB, node(), ram_copies),
    load(ClientsFile),
    {ok, #state{auth_cmd = AuthCmd, hash_type = HashType}}.

%% Try to auth by client_id
check(#mqtt_client{username = Username, client_id = ClientId, peername = {IpAddress, _}}, Password, _State)
    when ?UNDEFINED(Username) orelse ?UNDEFINED(Password) ->
    lager:debug("Client auth: ~s, ip ~s", [ClientId, inet_parse:ntoa(IpAddress)]),
    check_clientid_only(ClientId, IpAddress);

check(#mqtt_client{username = Username}, Password,
      #state{auth_cmd = AuthCmd, hash_type = HashType}) ->
    lager:debug("Redis auth ~s", [Username]),
    case emqttd_redis_client:query(repl_var(AuthCmd, Username)) of
        {ok, undefined} ->
            {error, not_found};
        {ok, HashPass} ->
            check_pass(HashPass, Password, HashType);
        {error, Error} ->
            {error, Error}
    end.

description() -> "Authentication with Redis".

check_pass(PassHash, Password, HashType) ->
    case PassHash =:= hash(HashType, Password) of
        true  -> ok;
        false -> {error, password_error}
    end.

hash(Type, Password) ->
    emqttd_auth_mod:passwd_hash(Type, Password).

repl_var(AuthCmd, Username) ->
    [re:replace(Token, "%u", Username, [global, {return, binary}]) || Token <- AuthCmd].

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

load(undefined) ->
    ok;

load(File) ->
    {ok, Fd} = file:open(File, [read]),
    load(Fd, file:read_line(Fd), []).

load(Fd, {ok, Line}, Clients) when is_list(Line) ->
    Clients1 =
    case string:tokens(Line, " ") of
        [ClientIdS] ->
            ClientId = list_to_binary(string:strip(ClientIdS, right, $\n)),
            [#mqtt_auth_clientid{client_id = ClientId} | Clients];
        [ClientId, IpAddr0] ->
            IpAddr = string:strip(IpAddr0, right, $\n),
            Range = esockd_access:range(IpAddr),
            [#mqtt_auth_clientid{client_id = list_to_binary(ClientId),
                                 ipaddr = {IpAddr, Range}}|Clients];
        BadLine ->
            lager:error("BadLine in clients.config: ~s", [BadLine]),
            Clients
    end,
    load(Fd, file:read_line(Fd), Clients1);

load(Fd, eof, Clients) ->
    mnesia:transaction(fun() -> [mnesia:write(C) || C<- Clients] end),
    file:close(Fd).

check_clientid_only(ClientId, IpAddr) ->
	%% Split client by # and authenticate only by first part
	%% E.g. Client id "SomeService#uniqueid" authenticates as "SomeService"
    ClientString = binary_to_list(ClientId),
    case string:tokens(ClientString, "#") of
        [ClientId2, _Suffix] ->
            check_clientid_only2(list_to_binary(ClientId2), IpAddr);
        [ClientId2] ->
            check_clientid_only2(list_to_binary(ClientId2), IpAddr);
        _ ->
            check_clientid_only2(ClientId, IpAddr)
    end.

check_clientid_only2(ClientId, IpAddr) ->
    %% lager:error("Authenticate against client id: ~s", [ClientId]),
    case mnesia:dirty_read(?AUTH_CLIENTID_TAB, ClientId) of
        [] -> {error, clientid_not_found};
        [#?AUTH_CLIENTID_TAB{ipaddr = undefined}]  -> ok;
        [#?AUTH_CLIENTID_TAB{ipaddr = {_, {Start, End}}}] ->
            I = esockd_access:atoi(IpAddr),
            case I >= Start andalso I =< End of
                true  -> ok;
                false -> {error, wrong_ipaddr}
            end
    end.

