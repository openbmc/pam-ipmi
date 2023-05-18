ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~

sysconf_DATA = key_file ipmi_pass_32 ipmi_pass_64

FILE_32 := ipmi_pass_32
FILE_64 := ipmi_pass_64

CP_FILE := $(FILE_$(TARGET_OS_ARCH))

install-exec-hook:
	cp $(DESTDIR)$(sysconfdir)/$(CP_FILE) $(DESTDIR)$(sysconfdir)/ipmi_pass
	rm $(DESTDIR)$(sysconfdir)/ipmi_pass_64
	rm $(DESTDIR)$(sysconfdir)/ipmi_pass_32
	chmod 0600 $(DESTDIR)$(sysconfdir)/key_file
	chmod 0600 $(DESTDIR)$(sysconfdir)/ipmi_pass

securelibdir = ${libdir}/security
securelib_LTLIBRARIES = pam_ipmicheck.la pam_ipmisave.la

pam_ipmicheck_la_SOURCES = src/pam_ipmicheck/pam_ipmicheck.c
pam_ipmicheck_la_LDFLAGS = \
	-module \
	-avoid-version \
	-shared \
	$(LIBS)

pam_ipmisave_la_SOURCES = src/pam_ipmisave/pam_ipmisave.c
pam_ipmisave_la_LDFLAGS = \
	-module \
	-avoid-version \
	-shared \
	$(LIBS) \
	$(OPENSSL_LIBS)
