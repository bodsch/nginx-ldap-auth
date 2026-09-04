# Maintainer: Bodo Schulz <bodo@boone-schulz.de>

pkgname=nginx-ldap-auth
pkgver=0.1.0
pkgrel=1
pkgdesc='LDAP authentication service for nginx auth_request'
arch=('x86_64' 'aarch64')
url='https://git.boone-schulz.de/go/nginx-ldap-auth'
license=('AGPL-3.0-or-later')

# nginx is deliberately not a dependency. The service is useful without it
# during configuration and testing, the nginx package needs no modification to
# work with it, and a package that pulls in a web server because it can be used
# behind one is a package that decides too much.
#
# glibc is needed even though cgo is off: -buildmode=pie below produces a
# dynamically linked binary that wants the glibc loader. The upstream release
# tarballs, built without PIE, are static and need nothing — this package trades
# that for ASLR, which is the right trade for a distribution package and the
# wrong one for a binary that has to run on any distribution.
depends=('glibc')
optdepends=(
  'nginx: the reverse proxy this service answers auth_request for'
  'redis: shared decision cache, only needed for more than one instance'
)
makedepends=('go' 'git')
checkdepends=('gcc')

backup=('etc/nginx-ldap-auth/config.yaml')
install="${pkgname}.install"

source=(
  "${pkgname}-${pkgver}.tar.gz::${url}/archive/v${pkgver}.tar.gz"
)

# Filled in with `updpkgsums` after a tag is pushed. SKIP would make the
# download unverified, which for a package that authenticates users is the wrong
# default to leave lying around.
sha256sums=('SKIP')

prepare() {
  cd "${pkgname}"
  # Vendoring at prepare time keeps build() offline, which is what makepkg in a
  # clean chroot expects and what makes the build reproducible from the tarball
  # alone.
  go mod download
}

build() {
  cd "${pkgname}"

  # CGO stays off. Not for portability — this is a distribution package — but
  # because the systemd unit sets MemoryDenyWriteExecute=true, and the comment
  # in the unit says that is safe for a binary built without cgo. Turning cgo on
  # here would make the unit's own documentation wrong.
  #
  # PIE is kept, since it works with internal linking on both packaged
  # architectures and is what gives the binary ASLR. This deviates from the
  # distribution's Go guidelines, which reach PIE by way of an external linker
  # and therefore cgo; the trade is stated above.
  export CGO_ENABLED=0
  export GOFLAGS="-buildmode=pie -mod=readonly -modcacherw -trimpath"

  # Through make, so that the build flags and the version stamping have one
  # definition rather than two that can disagree.
  make build VERSION="${pkgver}-${pkgrel}"
}

check() {
  cd "${pkgname}"

  # The race detector needs cgo and a C compiler, hence the checkdepends entry.
  # This is the same suite CI runs, minus the GLAuth integration tests: those
  # need a binary that is not a build dependency, and they skip themselves when
  # it is absent.
  CGO_ENABLED=1 go test -race -count=1 ./...
}

package() {
  cd "${pkgname}"

  # Everything is installed by the Makefile. The layout has one definition, in
  # one file, and it is exercised by a test — which a second copy of these
  # paths here would not be. That test exists because the unit named a binary
  # this function put somewhere else, and nothing noticed until it was run.
  make install-files \
    DESTDIR="${pkgdir}" \
    PREFIX=/usr \
    SYSCONFDIR=/etc
}
