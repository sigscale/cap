## Makefile.am
##
## Process this file with automake to produce Makefile.in

SUBDIRS = src asn_src ebin doc test

RELEASE_NAME = $(PACKAGE_NAME)-$(PACKAGE_VERSION)

.PHONY: release
release: $(RELEASE_NAME).tar.gz

$(RELEASE_NAME).rel: $(PACKAGE_NAME).rel
	cp $< $@

ERLTMP := $(shell mktemp -d)

if MAKE_TAR_EXTRA_FILES
$(RELEASE_NAME).tar.gz: $(RELEASE_NAME).rel ebin/$(PACKAGE_NAME).appup sys.config
	mkdir -p $(ERLTMP)/lib/$(RELEASE_NAME)
	cp -r $(DESTDIR)/$(ERLANG_INSTALL_LIB_DIR)/$(RELEASE_NAME)/* $(ERLTMP)/lib/$(RELEASE_NAME)
	ERL_LIBS=$(ERLTMP)/lib:$(ERL_LIBS) RELDIR=releases $(ERL) \
			-noinput -boot_var OTPHOME lib \
			-eval "systools:make_script(\"$(RELEASE_NAME)\", \
					[{variables, [{\"OTPHOME\", \"$(ERLTMP)\"}]}])" \
			-eval "{ok, [{release, _, _, Apps}]} = file:consult(\"$(RELEASE_NAME).rel\"), \
					ExtraFiles = [{code:where_is_file(atom_to_list(App) ++ \".appup\"), \
							filename:join([lib, atom_to_list(App) ++ \"-\" ++ Vsn, ebin, \
									atom_to_list(App) ++ \".appup\"])} \
							|| {App, Vsn} <- Apps, \
							filelib:is_regular(code:where_is_file(atom_to_list(App) ++ \".appup\"))], \
					systools:make_tar(\"$(RELEASE_NAME)\", \
							[{dirs, [include,doc]}, {extra_files, ExtraFiles}])" \
			-s init stop
	rm -rf $(ERLTMP)
else
$(RELEASE_NAME).tar.gz: $(RELEASE_NAME).rel ebin/$(PACKAGE_NAME).appup sys.config
	mkdir -p $(ERLTMP)/lib/$(RELEASE_NAME)
	cp -r $(DESTDIR)/$(ERLANG_INSTALL_LIB_DIR)/$(RELEASE_NAME)/* $(ERLTMP)/lib/$(RELEASE_NAME)
	ERL_LIBS=$(ERLTMP)/lib:$(ERL_LIBS) RELDIR=releases $(ERL) \
			-noinput -boot_var OTPHOME lib \
			-eval "systools:make_script(\"$(RELEASE_NAME)\", \
					[{variables, [{\"OTPHOME\", \"$(ERLTMP)\"}]}])" \
			-eval "systools:make_tar(\"$(RELEASE_NAME)\", [{dirs, [include,doc]}])" \
			-s init stop
	rm -rf $(ERLTMP)
endif

install-data-hook: $(RELEASE_NAME).tar.gz
	$(MKDIR_P) $(DESTDIR)/$(reldir)
	$(INSTALL_DATA) $< $(DESTDIR)/$(reldir)

EXTRA_DIST = $(RELEASE_NAME).tar.gz

CLEANFILES = $(RELEASE_NAME).rel $(RELEASE_NAME).script $(RELEASE_NAME).boot $(RELEASE_NAME).tar.gz

