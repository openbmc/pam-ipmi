#
# https://github.com/openbmc/pam-ipmi
#
project(
    'pam_ipmi',
    'c',
    version: '0.1',
    meson_version: '>=0.57.0',
    default_options: ['werror=true', 'warning_level=3'],
)

root = meson.current_source_dir()

compiler = meson.get_compiler('c')

fam = target_machine.cpu_family()
pw_file = ''
if (fam == 'aarch64' or fam == 'mips64' or fam == 'ppc64' or
    fam == 'riscv64' or fam == 'sparc64' or fam == 'x86_64')
    pw_file = 'ipmi_pass_64'
elif (fam == 'arc' or fam == 'arm' or fam == 'mips' or
    fam == 'ppc' or fam == 'riscv32' or fam == 'sparc' or
    fam == 'x86')
    pw_file = 'ipmi_pass_32'
else
    error('unknown target architecture')
endif

# Dependencies
crypto = dependency('libcrypto', version: '>=3.0.0')
pam = compiler.find_library('pam', required: true)

# Subfolders
subdir('src/pam_ipmicheck')
subdir('src/pam_ipmisave')

install_data(
    sources: pw_file,
    rename: 'ipmi_pass',
    install_mode: 'rw-------',
    install_dir: get_option('sysconfdir'),
)
install_data(
    sources: 'key_file',
    install_mode: 'rw-------',
    install_dir: get_option('sysconfdir'),
)

