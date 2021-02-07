## Makefile.am
##
## Process this file with automake to produce Makefile.in

noinst_DATA =	cap_codec.erl
einclude_DATA = cap_codec.hrl

cap_codec.hrl: cap_codec.erl

cap_codec.erl:	$(top_srcdir)/asn_src/cap_codec.set.asn1
	$(ERLC) $(ERLCFLAGS) +noobj $<

CLEANFILES = $(noinst_DATA) cap_codec.asn1db cap_codec.hrl

