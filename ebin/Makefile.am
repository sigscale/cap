## Makefile.am
##
## Process this file with automake to produce Makefile.in

ERLCFLAGS += -I ${ERLANG_LIB_DIR_tcap}/include \
		-I ${ERLANG_LIB_DIR_map}/include

appdir = $(beamdir)
app_DATA = cap.app
EXTRA_DIST = cap.app

beam_DATA = CAP-gprsSSF-gsmSCF-pkgs-contracts-acs.beam \
		CAP-gsmSCF-gsmSRF-pkgs-contracts-acs.beam \
		CAP-gsmSSF-gsmSCF-pkgs-contracts-acs.beam \
		CAP-smsSSF-gsmSCF-pkgs-contracts-acs.beam \
		CAP-object-identifiers.beam \
		CAP-errorcodes.beam \
		CAP-operationcodes.beam \
		CAP-datatypes.beam \
		CS1-DataTypes.beam \
		CAMEL-datatypes.beam

%.beam:$(top_builddir)/src/%.erl
	$(ERLC) $(ERLCFLAGS) -I $(top_builddir)/src $<

%.app:   %.app-in
	sed -e 's/%APP_NAME%/$(PACKAGE_NAME)/' \
			-e 's/%APP_VERSION%/$(PACKAGE_VERSION)/' < $< > $@ 

CLEANFILES = $(beam_DATA) $(app_DATA)

