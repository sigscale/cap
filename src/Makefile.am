## Makefile.am
##
## Process this file with automake to produce Makefile.in

ASNCFLAGS = $(ERLCFLAGS) \
		-I ${ERLANG_LIB_DIR_tcap}/asn_src \
		-I ${ERLANG_LIB_DIR_map}/asn_src \
		+ber +noobj

noinst_DATA = CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.erl \
		CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.erl \
		CAP-smsSSF-gsmSCF-pkgs-contracts-acs.erl \
		CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.erl \
		CAP-object-identifiers.erl \
		CAP-errorcodes.erl \
		CAP-operationcodes.erl \
		CS1-DataTypes.erl \
		CS2-datatypes.erl

einclude_DATA = CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.hrl \
		CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.hrl \
		CAP-smsSSF-gsmSCF-pkgs-contracts-acs.hrl \
		CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.hrl \
		CAP-object-identifiers.hrl \
		CAP-errorcodes.hrl \
		CAP-operationcodes.hrl \
		CS1-DataTypes.hrl \
		CS2-datatypes.hrl

CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.erl CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.hrl: \
		$(top_srcdir)/asn_src/CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.asn1
	$(ERLC) $(ASNCFLAGS) $<
	sed -e "/^-record('EXTERNAL'/,/^})\./d" \
			CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.hrl \
			> CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.hrl.tmp
	mv CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.hrl.tmp \
			CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.hrl

CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.erl CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.hrl: \
		$(top_srcdir)/asn_src/CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.asn1
	$(ERLC) $(ASNCFLAGS) $<
	sed -e "/^-record('EXTERNAL'/,/^})\./d" \
			CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.hrl \
			> CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.hrl.tmp
	mv CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.hrl.tmp \
			CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.hrl

CAP-smsSSF-gsmSCF-pkgs-contracts-acs.erl CAP-smsSSF-gsmSCF-pkgs-contracts-acs.hrl: \
		$(top_srcdir)/asn_src/CAP-smsSSF-gsmSCF-pkgs-contracts-acs.asn1
	$(ERLC) $(ASNCFLAGS) $<
	sed -e "/^-record('EXTERNAL'/,/^})\./d" \
			CAP-smsSSF-gsmSCF-pkgs-contracts-acs.hrl \
			> CAP-smsSSF-gsmSCF-pkgs-contracts-acs.hrl.tmp
	mv CAP-smsSSF-gsmSCF-pkgs-contracts-acs.hrl.tmp \
			CAP-smsSSF-gsmSCF-pkgs-contracts-acs.hrl

CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.erl CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.hrl: \
		$(top_srcdir)/asn_src/CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.asn1
	$(ERLC) $(ASNCFLAGS) $<
	sed -e "/^-record('EXTERNAL'/,/^})\./d" \
			CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.hrl \
			> CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.hrl.tmp
	mv CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.hrl.tmp \
			CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.hrl

%.erl %.hrl:$(top_srcdir)/asn_src/%.asn1
	$(ERLC) $(ASNCFLAGS) $<

CLEANFILES = $(noinst_DATA) $(einclude_DATA)

