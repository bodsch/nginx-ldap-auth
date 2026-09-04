// Package packaging holds no code. It exists so that the deployment files —
// the systemd unit, the sysusers and tmpfiles fragments, the PKGBUILD and the
// Makefile's install target — can be asserted against each other.
//
// Nothing else can. Every one of those files is consumed by a different tool on
// a different machine, so a mismatch between them is invisible to the compiler,
// to the linter and to every other test in this repository. It surfaces when
// somebody installs the package and the service refuses to start.
package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot returns the repository root, so the tests can read files that are
// not Go sources.
func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s does not look like the repository root: %v", root, err)
	}

	return root
}

func read(t *testing.T, root, name string) string {
	t.Helper()

	contents, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	return string(contents)
}

// execPaths returns the binary each Exec* line in a unit invokes.
var execLine = regexp.MustCompile(`(?m)^Exec[A-Za-z]*=(\S+)`)

func execPaths(unit string) []string {
	var paths []string

	for _, match := range execLine.FindAllStringSubmatch(unit, -1) {
		paths = append(paths, match[1])
	}

	return paths
}

// installUnit runs `make install` into a throwaway DESTDIR and returns the
// installed unit together with the path the binary landed at.
//
// A real install rather than a parse of the Makefile: what matters is the tree
// that ends up on disk, and the only thing that reliably reports it is the
// command that produces it.
func installUnit(t *testing.T, prefix string) (unit string, binary string) {
	t.Helper()

	root := repoRoot(t)
	destdir := t.TempDir()

	// Its own BIN_DIR: the default is the repository's bin/, and a test that
	// writes there mutates state another test or a developer's shell may be
	// using at the same time.
	cmd := exec.Command("make", "install",
		"DESTDIR="+destdir, "PREFIX="+prefix, "BIN_DIR="+t.TempDir())
	cmd.Dir = root

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make install PREFIX=%s: %v\n%s", prefix, err, out)
	}

	installed := filepath.Join(destdir, "usr/lib/systemd/system/nginx-ldap-auth.service")

	contents, err := os.ReadFile(installed)
	if err != nil {
		t.Fatalf("read the installed unit: %v", err)
	}

	binary = filepath.Join(destdir, prefix, "bin/nginx-ldap-auth")
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("the binary was not installed at %s: %v", binary, err)
	}

	return string(contents), filepath.Join(prefix, "bin/nginx-ldap-auth")
}

// TestInstalledUnitPointsAtTheInstalledBinary is the promise that makes the
// package installable at all.
//
// The unit names an absolute path. If it does not match where the binary was
// put, the package installs cleanly, the operator follows the README, and
// `systemctl start` fails on ExecStartPre with "No such file or directory" —
// every time, on every machine, with nothing in the repository having been
// wrong enough for any other check to notice.
//
// Two prefixes, because that is exactly the drift: a source install goes to
// /usr/local by convention and a distribution package must go to /usr. A unit
// with one path baked in can only be right for one of them.
func TestInstalledUnitPointsAtTheInstalledBinary(t *testing.T) {
	for _, prefix := range []string{"/usr/local", "/usr", "/opt/nginx-ldap-auth"} {
		t.Run(prefix, func(t *testing.T) {
			unit, binary := installUnit(t, prefix)

			paths := execPaths(unit)
			if len(paths) == 0 {
				t.Fatal("the installed unit has no Exec lines")
			}

			for _, path := range paths {
				if path != binary {
					t.Errorf("the unit invokes %s but the binary was installed at %s", path, binary)
				}
			}
		})
	}
}

// TestPKGBUILDDoesNotDuplicateTheInstallLogic is what keeps the previous test
// meaningful for the package as well.
//
// The Makefile install target can be exercised here; makepkg cannot. So the
// PKGBUILD must not have an install sequence of its own to drift — it has to
// delegate, and then testing the Makefile tests both.
func TestPKGBUILDDoesNotDuplicateTheInstallLogic(t *testing.T) {
	pkgbuild := read(t, repoRoot(t), "PKGBUILD")

	packageFunc := between(pkgbuild, "package() {", "\n}")
	if packageFunc == "" {
		t.Fatal("no package() function found in the PKGBUILD")
	}

	if !strings.Contains(packageFunc, "make") {
		t.Error("package() does not delegate to make, so its install paths can drift " +
			"from the Makefile's with nothing able to notice")
	}

	// An `install -D` of the unit, the binary or a fragment means the
	// sequence has been duplicated after all.
	for _, duplicated := range []string{
		"systemd/", "sysusers", "tmpfiles", "usr/bin/", "usr/lib/",
	} {
		if strings.Contains(packageFunc, duplicated) {
			t.Errorf("package() installs %q itself; that path now exists in two files", duplicated)
		}
	}
}

// TestWorkflowsOnlyCallExistingMakeTargets: a renamed target breaks the
// pipeline on the next push, and nothing in the repository objects beforehand.
func TestWorkflowsOnlyCallExistingMakeTargets(t *testing.T) {
	root := repoRoot(t)
	makefile := read(t, root, "Makefile")

	targets := regexp.MustCompile(`(?m)^([a-z][a-z-]*):`)

	defined := make(map[string]bool)
	for _, match := range targets.FindAllStringSubmatch(makefile, -1) {
		defined[match[1]] = true
	}

	if !defined["build"] {
		t.Fatal("the target extraction found no 'build' target, so it is not working")
	}

	call := regexp.MustCompile(`make ([a-z][a-z-]*)`)

	for _, workflow := range workflowFiles(t, root) {
		contents := read(t, root, workflow)

		for _, match := range call.FindAllStringSubmatch(contents, -1) {
			if !defined[match[1]] {
				t.Errorf("%s calls `make %s`, which the Makefile does not define", workflow, match[1])
			}
		}
	}
}

// TestReleaseWorkflowsBundleFilesThatExist: the release job is the least-run
// code in the repository — it runs once per tag — and a missing file fails it
// after the tag is already pushed.
func TestReleaseWorkflowsBundleFilesThatExist(t *testing.T) {
	root := repoRoot(t)

	referenced := regexp.MustCompile(`(?m)(systemd|packaging|nginx)/[A-Za-z0-9._-]+|\bconfig\.example\.yaml\b|\bLICENSE\b|\bREADME\.md\b`)

	for _, workflow := range workflowFiles(t, root) {
		if !strings.Contains(workflow, "release") {
			continue
		}

		contents := read(t, root, workflow)

		for _, name := range referenced.FindAllString(contents, -1) {
			// Skip the ${PACKAGE_NAME} interpolations; they are
			// covered by the Makefile delegation test.
			if strings.Contains(name, "$") {
				continue
			}

			if _, err := os.Stat(filepath.Join(root, name)); err != nil {
				t.Errorf("%s bundles %s, which does not exist", workflow, name)
			}
		}
	}
}

// TestUnitUserMatchesTheSysusersFragment: the unit runs as a user that a
// different file is responsible for creating. If the two names diverge,
// systemd refuses to start the service with "Failed to determine user
// credentials".
func TestUnitUserMatchesTheSysusersFragment(t *testing.T) {
	root := repoRoot(t)

	unit := read(t, root, "systemd/nginx-ldap-auth.service")
	sysusers := read(t, root, "packaging/nginx-ldap-auth.sysusers")

	created := ""

	for _, line := range strings.Split(sysusers, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "u" {
			created = fields[1]
		}
	}

	if created == "" {
		t.Fatal("the sysusers fragment creates no user")
	}

	for _, key := range []string{"User", "Group"} {
		want := key + "=" + created
		if !strings.Contains(unit, want) {
			t.Errorf("the unit does not contain %q; systemd would refuse to start the service", want)
		}
	}
}

// TestTmpfilesCoversEverySecretTheExampleReferences.
//
// The fragment is what makes the secrets readable by the service user. A secret
// path the example configuration names but the fragment does not manage stays
// root-only, and the service fails to read it — at start-up if it is the
// pepper, and on the first authentication if it is the bind password.
func TestTmpfilesCoversEverySecretTheExampleReferences(t *testing.T) {
	root := repoRoot(t)

	tmpfiles := read(t, root, "packaging/nginx-ldap-auth.tmpfiles")
	example := read(t, root, "config.example.yaml")

	secret := regexp.MustCompile(`/etc/nginx-ldap-auth/[a-z-]+\.secret`)

	found := secret.FindAllString(example, -1)
	if len(found) == 0 {
		t.Fatal("the example configuration names no secret files, so this test is not working")
	}

	for _, path := range found {
		if !strings.Contains(tmpfiles, path) {
			t.Errorf("the example references %s but the tmpfiles fragment does not manage it, "+
				"so it would stay unreadable by the service user", path)
		}
	}
}

// TestPepperPathIsTheSameEverywhere: the install hook generates it, the
// tmpfiles fragment sets its mode, and the example configuration points at it.
// Three files, one path.
func TestPepperPathIsTheSameEverywhere(t *testing.T) {
	root := repoRoot(t)

	hook := read(t, root, "packaging/nginx-ldap-auth.install")

	assign := regexp.MustCompile(`(?m)^_pepper=(\S+)`)

	match := assign.FindStringSubmatch(hook)
	if match == nil {
		t.Fatal("the install hook does not assign _pepper")
	}

	path := match[1]

	for _, name := range []string{"packaging/nginx-ldap-auth.tmpfiles", "config.example.yaml"} {
		if !strings.Contains(read(t, root, name), path) {
			t.Errorf("%s does not mention %s, which the install hook generates", name, path)
		}
	}
}

// workflowFiles lists the CI and release workflows.
func workflowFiles(t *testing.T, root string) []string {
	t.Helper()

	var files []string

	for _, dir := range []string{".forgejo/workflows", ".github/workflows"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}

		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".yml") {
				files = append(files, filepath.Join(dir, entry.Name()))
			}
		}
	}

	if len(files) == 0 {
		t.Fatal("no workflow files found, so the workflow tests are not working")
	}

	return files
}

// between returns the text between the first occurrence of open and the next
// occurrence of close after it.
func between(s, open, close string) string {
	start := strings.Index(s, open)
	if start < 0 {
		return ""
	}

	rest := s[start+len(open):]

	end := strings.Index(rest, close)
	if end < 0 {
		return rest
	}

	return rest[:end]
}

// TestPepperIsGeneratedOnceAndNeverReplaced runs the package's install hook.
//
// This is the only secret the packaging creates, and both halves of its
// behaviour matter. It has to be generated, because a package that shipped one
// would give every installation the same secret — and a cache leaked from any of
// them would then be crackable against all the others, which is the property
// the pepper exists to provide. And it must never be replaced on upgrade,
// because that silently invalidates every cache entry on every package update.
//
// The hook is shell, so the test runs it as shell. Reading it and reasoning
// about it would assert what it looks like rather than what it does.
func TestPepperIsGeneratedOnceAndNeverReplaced(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available; the hook needs it to generate the pepper")
	}

	root := repoRoot(t)
	hook := read(t, root, "packaging/nginx-ldap-auth.install")

	// The hook writes to an absolute path under /etc. Redirected here so the
	// test does not need root and does not touch the machine it runs on.
	sandbox := t.TempDir()
	redirected := strings.Replace(hook,
		"_pepper=/etc/nginx-ldap-auth/cache-pepper.secret",
		"_pepper="+filepath.Join(sandbox, "cache-pepper.secret"), 1)

	if redirected == hook {
		t.Fatal("the pepper path was not redirected, so this test would write to /etc")
	}

	script := filepath.Join(sandbox, "hook.sh")

	// Source the hook, then call the entry points a package manager calls.
	body := redirected + "\n\n" + `case "$1" in
	install) post_install ;;
	upgrade) post_upgrade ;;
	esac
`

	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	pepper := filepath.Join(sandbox, "cache-pepper.secret")

	runHook := func(phase string) {
		t.Helper()

		cmd := exec.Command("bash", script, phase)

		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("hook %s: %v\n%s", phase, err, out)
		}
	}

	runHook("install")

	first, err := os.ReadFile(pepper)
	if err != nil {
		t.Fatalf("the hook did not generate a pepper: %v", err)
	}

	// 32 bytes as hex. The loader refuses anything shorter, so a hook that
	// generated less would produce a package that cannot start.
	if len(strings.TrimSpace(string(first))) != 64 {
		t.Errorf("pepper is %d characters, want 64 (32 bytes as hex)", len(strings.TrimSpace(string(first))))
	}

	info, err := os.Stat(pepper)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// The service warns about anything accessible to "other", and it is
	// right to. A hook that created the file with a loose mode would make
	// every fresh installation start with a warning.
	if mode := info.Mode().Perm(); mode&0o007 != 0 {
		t.Errorf("pepper mode is %04o, accessible to every user on the system", mode)
	}

	runHook("upgrade")

	second, err := os.ReadFile(pepper)
	if err != nil {
		t.Fatalf("read after upgrade: %v", err)
	}

	if string(second) != string(first) {
		t.Error("the upgrade replaced the pepper; every cache entry on every host would be " +
			"invalidated by a package update")
	}

	// And an installation whose pepper went missing gets one back, rather
	// than a service that refuses to start.
	if err := os.Remove(pepper); err != nil {
		t.Fatalf("remove: %v", err)
	}

	runHook("upgrade")

	third, err := os.ReadFile(pepper)
	if err != nil {
		t.Fatalf("the upgrade did not restore a missing pepper: %v", err)
	}

	if string(third) == string(first) {
		t.Error("the restored pepper is identical to the removed one, which cannot be random")
	}
}
