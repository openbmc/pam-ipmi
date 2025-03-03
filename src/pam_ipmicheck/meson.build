#
# build a pam library
#
libpam_ipmicheck = library(
    'pam_ipmicheck',
    'pam_ipmicheck.c',
    dependencies: [pam, crypto],
    soversion: '',
    name_prefix: '',
    install: true,
    install_dir: get_option('libdir') / 'security',
)
