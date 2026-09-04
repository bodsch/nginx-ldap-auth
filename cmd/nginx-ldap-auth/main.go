// Command nginx-ldap-auth is an LDAP authentication service for nginx's
// auth_request module.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	"git.boone-schulz.de/go/nginx-ldap-auth/internal/auth"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/cache"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/config"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/policy"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/ratelimit"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/server"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "nginx-ldap-auth: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("nginx-ldap-auth", flag.ContinueOnError)
	flags.SetOutput(stderr)

	configPath := flags.String("config", "/etc/nginx-ldap-auth/config.yaml", "path to the configuration file")
	checkOnly := flags.Bool("check", false, "validate the configuration and exit without listening")
	showVersion := flags.Bool("version", false, "print the version and exit")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		fmt.Fprintf(stdout, "nginx-ldap-auth %s (%s, %s/%s)\n",
			version, runtime.Version(), runtime.GOOS, runtime.GOARCH)

		return nil
	}

	cfg, warnings, err := config.Load(*configPath)

	// Warnings are reported even when loading failed: a bad file mode found
	// alongside a validation error is still worth fixing in the same pass.
	for _, warning := range warnings {
		fmt.Fprintf(stderr, "warning: %s\n", warning)
	}

	if err != nil {
		return err
	}

	if *checkOnly {
		fmt.Fprintf(stdout, "%s is valid: %d policies, %d directories\n",
			*configPath, len(cfg.Policies), len(cfg.LDAP))

		return nil
	}

	log := newLogger(cfg.Logging, stdout)

	// Re-logged through the structured logger so that the journal carries
	// them in the same form as everything else. The plain-text copy above
	// is what an operator running --check sees.
	for _, warning := range warnings {
		log.Warn("configuration warning", slog.String("detail", warning))
	}

	return serve(cfg, log)
}

// serve builds every component and runs the listener until a signal arrives.
func serve(cfg *config.Config, log *slog.Logger) error {
	policies, err := policy.NewSet(cfg)
	if err != nil {
		return fmt.Errorf("prepare policies: %w", err)
	}

	decisionCache, keyer, err := newCache(cfg.Cache)
	if err != nil {
		return fmt.Errorf("prepare cache: %w", err)
	}

	throttle, err := newThrottle(cfg.RateLimit)
	if err != nil {
		return fmt.Errorf("prepare throttle: %w", err)
	}

	directories, closeDirectories, err := auth.Directories(cfg, log)
	if err != nil {
		return fmt.Errorf("prepare directories: %w", err)
	}

	defer func() {
		for _, release := range closeDirectories {
			release()
		}
	}()

	authenticator, err := auth.New(auth.Options{
		Policies:    policies,
		Directories: directories,
		Cache:       decisionCache,
		Keyer:       keyer,
		Throttle:    throttle,
		PositiveTTL: cfg.Cache.TTL.Duration(),
		NegativeTTL: cfg.Cache.NegativeTTL.Duration(),
		Logger:      log,
	})
	if err != nil {
		return fmt.Errorf("prepare authenticator: %w", err)
	}

	srv, err := server.New(server.Options{
		Config:        cfg.Server,
		Authenticator: authenticator,
		Cache:         decisionCache,
		Throttle:      throttle,
		LogUsername:   cfg.Logging.LogUsername,
		Logger:        log,
	})
	if err != nil {
		return fmt.Errorf("prepare server: %w", err)
	}

	logStartup(log, cfg, policies, decisionCache)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Serve(ctx); err != nil {
		return err
	}

	log.Info("stopped")

	return nil
}

// newCache returns the decision cache and the keyer that derives its keys.
func newCache(cfg config.Cache) (cache.Cache, *cache.Keyer, error) {
	if !cfg.Enabled {
		return cache.Disabled{}, nil, nil
	}

	keyer, err := cache.NewKeyer(cfg.Pepper)
	if err != nil {
		return nil, nil, fmt.Errorf("cache keyer: %w", err)
	}

	memory, err := cache.NewMemory(cfg.MaxEntries)
	if err != nil {
		return nil, nil, err
	}

	return memory, keyer, nil
}

// newThrottle returns the failure throttle.
func newThrottle(cfg config.RateLimit) (ratelimit.Throttle, error) {
	if !cfg.Enabled {
		return ratelimit.Disabled{}, nil
	}

	return ratelimit.New(ratelimit.Config{
		Window:                cfg.Window.Duration(),
		BlockDuration:         cfg.BlockDuration.Duration(),
		MaxFailuresPerUser:    cfg.MaxFailuresPerUser,
		MaxFailuresPerAddress: cfg.MaxFailuresPerIP,
		MaxEntries:            cfg.MaxEntries,
	})
}

// newLogger builds the structured logger.
func newLogger(cfg config.Logging, out io.Writer) *slog.Logger {
	level := slog.LevelInfo

	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler = slog.NewJSONHandler(out, opts)
	if cfg.Format == "text" {
		handler = slog.NewTextHandler(out, opts)
	}

	return slog.New(handler)
}

// logStartup records what the service is actually going to do, so that a
// misconfiguration is visible in the journal without reading the config file.
func logStartup(log *slog.Logger, cfg *config.Config, policies *policy.Set, decisionCache cache.Cache) {
	log.Info("starting",
		slog.String("version", version),
		slog.String("go", runtime.Version()),
		slog.String("revision", revision()),
	)

	log.Info("configuration loaded",
		slog.Any("policies", policies.Names()),
		slog.String("default_policy", policies.DefaultName()),
		slog.Int("directories", len(cfg.LDAP)),
		slog.String("cache", decisionCache.Name()),
		slog.String("cache_ttl", cfg.Cache.TTL.String()),
		slog.String("negative_ttl", cfg.Cache.NegativeTTL.String()),
		slog.Bool("throttle", cfg.RateLimit.Enabled),
	)

	// Without a default policy, every protected location has to set the
	// header. That is the safer arrangement and also the one most likely to
	// be forgotten, so it is stated rather than left to be discovered
	// through 403s.
	if policies.DefaultName() == "" {
		log.Info("no default policy configured: every nginx location must set the "+policy.Header+" header",
			slog.Any("policies", policies.Names()))
	}
}

// revision reports the VCS revision the binary was built from, when the build
// recorded one.
func revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}

	return "unknown"
}
