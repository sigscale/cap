## Makefile.am
## vim: ts=3
##
## Process this file with automake to produce Makefile.in

testmods = cap_codec_SUITE

check_DATA = .dialyzer_ok .common_test_ok

.dialyzer_ok:	$(addsuffix .beam, $(testmods))
	dialyzer --src $(top_builddir)/src

%.beam:$(top_srcdir)/test/%.erl
	$(ERLC) $(ERLCFLAGS) -I $(top_builddir)/src $<

.common_test_ok:	$(addsuffix .beam, $(testmods))
	@if [ ! -d log ]; then mkdir log; fi
	@if [ ! -f ct.cfg ]; then cp $(top_srcdir)/test/ct.cfg .; fi
	@if [ ! -f test.spec ]; then cp $(top_srcdir)/test/test.spec .; fi
	ct_run -no_auto_compile \
			-pa $(top_builddir)/ebin \
			-logdir log -config ct.cfg -spec test.spec -dir . \
			-erl_args -noshell -sname $(LOGNAME)-ct

clean-local:
	-rm -r *.beam log/*

