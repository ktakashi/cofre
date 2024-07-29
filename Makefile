.PHONY: install library gen-cli uninstall clean
.DEFAULT_GOAL := all

DEST_DIR := ~/.scheme-env/bin
SAGITTARIUS_VERSION := 0.9.11
TEMP_CLI = cofre-cli.tmp
INSTALL := install

all: install

install: library gen-cli
	$(INSTALL) -m0755 $(TEMP_CLI) $(DEST_DIR)/cofre-cli
	$(INSTALL) -m0644 cofre-cli.scm $(DEST_DIR)/cofre-cli.scm

library:
	scheme-env sitelib -i sagittarius cofre lib

uninstall:
	-$(RM) $(DEST_DIR)/cofre-cli
	-$(RM) $(DEST_DIR)/cofre-cli.scm
	scheme-env sitelib -d cofre

gen-cli: cofre-cli.tmp

cofre-cli.tmp:
	echo '#/bin/bash' > $@
	echo 'scheme-env run sagittarius@$(SAGITTARIUS_VERSION) -- cofre-cli.scm' >> $@

clean:
	$(RM) $(TEMP_CLI)
