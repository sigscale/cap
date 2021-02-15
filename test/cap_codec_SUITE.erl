%%% cap_codec_SUITE.erl
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2021 SigScale Global Inc.
%%% @end
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Test suite for the CAMEL Application Part (CAP) CODEC
%%% of the {@link //cap. cap} application.
%%%
-module(cap_codec_SUITE).
-copyright('Copyright (c) 2021 SigScale Global Inc.').
-author('Vance Shipley <vances@sigscale.org>').

%% common_test required callbacks
-export([suite/0, sequences/0, all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
%% common_test optional callbacks
-export([init_per_group/2, end_per_group/2, groups/0, group/1]).
%% common_test test cases
-export([decode_pdu/0, decode_pdu/1, encode_pdu/0, encode_pdu/1]).

-include("../src/CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.hrl").
-include("../src/CAP-object-identifiers.hrl").
-include("../src/CAP-operationcodes.hrl").
-include("../src/CAP-datatypes.hrl").
-include("../src/CAMEL-datatypes.hrl").
-include_lib("tcap/include/TC.hrl").
-include_lib("tcap/include/TR.hrl").
-include_lib("tcap/include/DialoguePDUs.hrl").
-include_lib("common_test/include/ct.hrl").

%%---------------------------------------------------------------------
%%  Test server callback functions
%%---------------------------------------------------------------------

-spec suite() -> DefaultData :: [tuple()].
%% Require variables and set default values for the suite.
%%
suite() ->
	[{userdata, [{doc,
			"Encoding and decoding of CAP PDUs"}]},
			{timetrap, {minutes, 1}}].

-spec init_per_suite(Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before the whole suite.
%%
init_per_suite(Config) ->
   Config.

-spec end_per_suite(Config :: [tuple()]) -> any().
%% Cleanup after the whole suite.
%%
end_per_suite(_Config) ->
	ok.

-spec init_per_group(Group :: atom(), Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before each test group.
%%
init_per_group(_Group, Config) ->
	Config.

-spec end_per_group(Group :: atom(), Config :: [tuple()]) -> any().
%% Cleanup after each test group.
%%
end_per_group(_Group, _Config) ->
	ok.

-spec init_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before each test case.
%%
init_per_testcase(_TestCase, Config) ->
	Config.

-spec end_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> any().
%% Cleanup after each test case.
%%
end_per_testcase(_TestCase, _Config) ->
	ok.

-spec sequences() -> Sequences :: [{SeqName :: atom(), Testcases :: [atom()]}].
%% Group test cases into a test sequence.
%%
sequences() ->
	[].

-spec all() -> TestCases :: [Case :: atom()].
%% Returns a list of all test cases in this test suite.
%%
all() ->
	[decode_pdu, encode_pdu].

-spec group(GroupName) -> [Info]
	when
		GroupName :: atom(),
		Info :: term().
%% @doc Test case group information.
group(_GroupName) ->
	[].

-spec groups() -> GroupDefs
	when
		GroupDefs :: [Group],
		Group :: {GroupName, Properties, GroupsAndTestCases},
		GroupName :: atom(),
		Properties :: [parallel | sequence | Shuffle | {GroupRepeatType, N}],
		GroupsAndTestCases :: [Group | {group, GroupName}
				| TestCase | {testcase, TestCase, TCRepeatProps}],
		TestCase :: atom(),
		TCRepeatProps :: [{repeat, N} | {repeat_until_ok, N}
				| {repeat_until_fail, N}],
		Shuffle :: shuffle | {shuffle, Seed},
		Seed :: {integer(), integer(), integer()},
		GroupRepeatType :: repeat | repeat_until_all_ok | repeat_until_all_fail
				| repeat_until_any_ok | repeat_until_any_fail,
		N :: integer() | forever.
%% @doc Define test case groups.
%%
groups() ->
	[].

%%---------------------------------------------------------------------
%%  Test cases
%%---------------------------------------------------------------------

decode_pdu() ->
	[{userdata,
			[{description, "Decode PDU containing InitialDP"}]}].

decode_pdu(Config) ->
	PDU = pdu_initial_dp(),
	{ok, {'begin', Begin}} = 'TR':decode('TCMessage', PDU),
	#'EXTERNAL'{encoding = Encoding} = Begin#'Begin'.dialoguePortion,
	{'single-ASN1-type', DialoguePDU} = Encoding,
	{ok, {dialogueRequest, AARQ}} = 'DialoguePDUs':decode('DialoguePDU', DialoguePDU),
	#'AARQ-apdu'{'application-context-name' = ?'id-ac-CAP-gsmSSF-scfGenericAC'} = AARQ,
	{ok, [{invoke, Invoke}]} = 'TC':decode('Components', Begin#'Begin'.components),
	#'Invoke'{argument = Argument} = Invoke,
	{ok, IDP} = 'CAP-gsmSSF-gsmSCF-pkgs-contracts-acs':decode('GenericSSF-gsmSCF-PDUs_InitialDPArg', Argument),
	<<129,16,65,97,85,21,50,4>> =  IDP#'GenericSSF-gsmSCF-PDUs_InitialDPArg'.callingPartyNumber,
	<<129,19,65,97,85,21,50,4>> = IDP#'GenericSSF-gsmSCF-PDUs_InitialDPArg'.locationNumber,
	<<0,1,16,16,50,84,118,152>> = IDP#'GenericSSF-gsmSCF-PDUs_InitialDPArg'.iMSI,
	<<161,65,97,85,85,118,248>> = IDP#'GenericSSF-gsmSCF-PDUs_InitialDPArg'.calledPartyBCDNumber.

encode_pdu() ->
	[{userdata,
			[{description, "Decode PDU containing InitialDP"}]}].

encode_pdu(Config) ->
	BCSMEvents = [#'GenericSCF-gsmSSF-PDUs_RequestReportBCSMEventArg_bcsmEvents_SEQOF'{
					eventTypeBCSM = routeSelectFailure,
					monitorMode = notifyAndContinue,
					legID = asn1_NOVALUE,
					dpSpecificCriteria = asn1_NOVALUE,
					automaticRearm = asn1_NOVALUE},
			#'GenericSCF-gsmSSF-PDUs_RequestReportBCSMEventArg_bcsmEvents_SEQOF'{
					eventTypeBCSM = oCalledPartyBusy,
					monitorMode = notifyAndContinue,
					legID = asn1_NOVALUE,
					dpSpecificCriteria = asn1_NOVALUE,
					automaticRearm = asn1_NOVALUE},
			#'GenericSCF-gsmSSF-PDUs_RequestReportBCSMEventArg_bcsmEvents_SEQOF'{
					eventTypeBCSM = oNoAnswer,
					monitorMode = notifyAndContinue,
					legID = asn1_NOVALUE,
					dpSpecificCriteria = asn1_NOVALUE,
					automaticRearm = asn1_NOVALUE},
			#'GenericSCF-gsmSSF-PDUs_RequestReportBCSMEventArg_bcsmEvents_SEQOF'{
					eventTypeBCSM = oAnswer,
					monitorMode = notifyAndContinue,
					legID = asn1_NOVALUE,
					dpSpecificCriteria = asn1_NOVALUE,
					automaticRearm = asn1_NOVALUE},
			#'GenericSCF-gsmSSF-PDUs_RequestReportBCSMEventArg_bcsmEvents_SEQOF'{
					eventTypeBCSM = oDisconnect,
					monitorMode = notifyAndContinue,
					legID = asn1_NOVALUE,
					dpSpecificCriteria = asn1_NOVALUE,
					automaticRearm = asn1_NOVALUE},
			#'GenericSCF-gsmSSF-PDUs_RequestReportBCSMEventArg_bcsmEvents_SEQOF'{
					eventTypeBCSM = oAbandon,
					monitorMode = notifyAndContinue,
					legID = asn1_NOVALUE,
					dpSpecificCriteria = asn1_NOVALUE,
					automaticRearm = asn1_NOVALUE}],
	RequestReportBCSMEventArg = #'GenericSCF-gsmSSF-PDUs_RequestReportBCSMEventArg'{bcsmEvents = BCSMEvents},
	BasicROS1 = #'GenericSCF-gsmSSF-PDUs_continue_components_SEQOF_basicROS_invoke'{
			invokeId = {present, 1},
			opcode = ?'opcode-requestReportBCSMEvent',
			argument = RequestReportBCSMEventArg},
	CallInformationRequestArg = #'GenericSCF-gsmSSF-PDUs_CallInformationRequestArg'{
			requestedInformationTypeList = [callAttemptElapsedTime,
					callStopTime, callConnectedElapsedTime, releaseCause]},
	BasicROS2 = #'GenericSCF-gsmSSF-PDUs_continue_components_SEQOF_basicROS_invoke'{
			invokeId = {present, 2},
			opcode = ?'opcode-callInformationRequest',
			argument = CallInformationRequestArg},
	TimeDurationCharging = #'PduAChBillingChargingCharacteristics_timeDurationCharging'{
			maxCallPeriodDuration = 300},
	{ok, PduAChBillingChargingCharacteristics} = 'CAMEL-datatypes':encode(
			'PduAChBillingChargingCharacteristics', {timeDurationCharging, TimeDurationCharging}),
	ApplyChargingArg = #'GenericSCF-gsmSSF-PDUs_ApplyChargingArg'{
			aChBillingChargingCharacteristics = PduAChBillingChargingCharacteristics,
			partyToCharge = {sendingSideID, ?leg1}},
	BasicROS3 = #'GenericSCF-gsmSSF-PDUs_continue_components_SEQOF_basicROS_invoke'{
			invokeId = {present, 3},
			opcode = ?'opcode-applyCharging',
			argument = ApplyChargingArg},
	BasicROS4 = #'GenericSCF-gsmSSF-PDUs_continue_components_SEQOF_basicROS_invoke'{
			invokeId = {present, 4},
			opcode = ?'opcode-continue'},
	Continue = #'GenericSCF-gsmSSF-PDUs_continue'{otid = tid(), dtid = tid(),
			components = [{basicROS, {invoke, BasicROS1}},
					{basicROS, {invoke, BasicROS2}},
					{basicROS, {invoke, BasicROS3}},
					{basicROS, {invoke, BasicROS4}}]},
	{ok, SccpUnitData} = 'CAP-gsmSSF-gsmSCF-pkgs-contracts-acs':encode('GenericSSF-gsmSCF-PDUs',
			{'continue', Continue}),
	true = is_binary(SccpUnitData).

%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------

tid() ->
	TID = rand:uniform(16#ffffffff),
	<<TID:32>>.

pdu_initial_dp() ->
	<<98,129,167,72,4,129,35,175,209,107,30,40,28,6,7,0,17,134,5,1,1,1,
			160,17,96,15,128,2,7,128,161,9,6,7,4,0,0,1,23,3,4,108,127,161,
			125,2,1,1,2,1,0,48,117,128,1,91,131,8,129,16,65,97,85,21,50,4,
			133,1,10,138,8,129,19,65,97,85,21,50,4,187,5,128,3,128,144,163,
			156,1,2,159,50,8,0,1,16,16,50,84,118,152,191,52,23,2,1,0,129,7,
			193,65,97,85,5,0,240,163,9,128,7,0,1,16,0,1,0,1,191,53,3,131,1,
			17,159,54,4,9,4,193,244,159,55,7,193,65,97,85,5,0,240,159,56,7,
			161,65,97,85,85,118,248,159,57,8,2,18,32,65,81,116,49,10>>.

