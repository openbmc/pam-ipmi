#
# build a pam library
#
libpam_ipmisave = library(
    'pam_ipmisave',
    'pam_ipmisave.c',
    dependencies: [pam, crypto],
    soversion: '',
    name_prefix: '',
    install: true,
    install_dir: get_option('libdir') / 'security',
)
