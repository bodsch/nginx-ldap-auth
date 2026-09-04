# Packaging

## Arch Linux

```sh
# From a tagged release:
updpkgsums          # replaces the SKIP placeholder with the real checksum
makepkg -si

# For the AUR, if it is ever published there:
makepkg --printsrcinfo > .SRCINFO
```

`.SRCINFO` is deliberately not committed. It is generated from the `PKGBUILD`
and goes stale the moment `pkgver` changes, so a committed copy is a file that
is wrong more often than right.

The three fragments the `PKGBUILD` installs do the work that would otherwise sit
in a shell script:

| File | Applied by | What it does |
|---|---|---|
| `nginx-ldap-auth.sysusers` | `systemd-sysusers` pacman hook | creates the unprivileged system user |
| `nginx-ldap-auth.tmpfiles` | `systemd-tmpfiles` pacman hook | sets the mode and group of `/etc/nginx-ldap-auth` and the files in it |
| `nginx-ldap-auth.install` | pacman | generates the cache pepper, once |

The pepper is the one thing that cannot be declarative. It must not exist in the
package: every installation would then share one secret, and a cache leaked from
any of them would be crackable against all the others — which is the property
the pepper exists to provide in the first place. So it is generated on the
target machine, on first install, and never regenerated on upgrade.

## Other distributions

`make install` places the same files under `/usr/local` by default, and honours
`DESTDIR`, `PREFIX`, `SYSCONFDIR`, `UNITDIR` and `SYSUSERSDIR`. It does not
create the system user or generate the pepper; `make pepper` does the second.
