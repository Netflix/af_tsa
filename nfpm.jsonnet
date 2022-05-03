local srcdir = std.rstripChars(std.extVar('srcdir'), '/') + '/';

std.manifestYamlDoc({
  name: 'aftsa',
  arch: 'amd64',
  platform: 'linux',
  version: std.extVar('version'),
  section: 'default',
  priority: 'extra',
  depends: ['dkms'],
  maintainer: 'Sargun Dhillon <sargun@sargun.me>',
  description: 'Kernel Module for AF TSA',
  license: '(GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause-No-Nuclear-Warranty',
  provides: ['aftsa2', 'aftsa0' + std.extVar('buildtime')],
  scripts: {
    postinstall: 'tmp/postInstall.sh',
    preremove: 'tmp/preRemove.sh',
  },
  contents: [
    {
      src: 'tmp/dkms.conf',
      dst: srcdir + 'dkms.conf',
    },
    {
      src: 'src',
      dst: srcdir,
    },
    {
      src: 'src/include/uapi',
      dst: '/usr/include/af_tsa',
    },
  ],
}, indent_array_in_object=true)
