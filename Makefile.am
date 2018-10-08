CLEANFILES = *~

sysconf_DATA = key_file
securelibdir = /lib/security
securelib_LTLIBRARIES = pam_ipmicheck.la pam_ipmisave.la

pam_ipmicheck_la_SOURCES = src/pam_ipmicheck/pam_ipmicheck.c
pam_ipmicheck_la_LDFLAGS = -module -avoid-version -shared
pam_ipmicheck_LDADD = $(LIBPAM) $(LIBCRYPT)

pam_ipmisave_la_SOURCES = src/pam_ipmisave/pam_ipmisave.c
pam_ipmisave_la_LDFLAGS = -module -avoid-version -shared -lssl
pam_ipmisave_LDADD = $(LIBPAM) $(LIBCRYPT)
