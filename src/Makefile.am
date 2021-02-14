## Makefile.am
##
## Process this file with automake to produce Makefile.in

noinst_DATA =	CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.erl \
		CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.erl \
		CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.erl \
		CAP-smsSSF-gsmSCF-pkgs-contracts-acs.erl \
		CAP-object-identifiers.erl \
		CAP-errorcodes.erl \
		CAP-operationcodes.erl

einclude_DATA = CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.hrl \
		CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.hrl \
		CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.hrl \
		CAP-smsSSF-gsmSCF-pkgs-contracts-acs.hrl \
		CAP-object-identifiers.hrl \
		CAP-errorcodes.hrl \
		CAP-operationcodes.hrl

%.erl %.hrl:$(top_srcdir)/asn_src/%.asn1
	$(ERLC) $(ERLCFLAGS) +ber +noobj $<

CLEANFILES = $(noinst_DATA) $(einclude_DATA)

