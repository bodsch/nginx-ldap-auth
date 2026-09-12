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
	"time"

	"bodsch.me/nginx-ldap-auth/internal/auth"
	"bodsch.me/nginx-ldap-auth/internal/cache"
	"bodsch.me/nginx-ldap-auth/internal/config"
	"bodsch.me/nginx-ldap-auth/internal/ldap"
	"bodsch.me/nginx-ldap-auth/internal/metrics"
	"bodsch.me/nginx-ldap-auth/internal/policy"
	"bodsch.me/nginx-ldap-auth/internal/ratelimit"
	"bodsch.me/nginx-ldap-auth/internal/server"
)

// version and buildDate are stamped at build time with
//
//	-ldflags "-X main.version=... -X main.buildDate=..."
//
// buildDate is a UTC day rather than a timestamp: it keeps two builds of the
// same release comparable, and it is coarse enough not to make an otherwise
// identical rebuild differ by the second.
var (
	version   = "dev"
	buildDate = "unknown"
)

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
		fmt.Fprintf(stdout, "nginx-ldap-auth %s (built %s, %s, %s/%s, revision %s)\n",
			version, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH, revision())

		return nil
	}

	cfg, warnings, err := config.Load(*configPath)

	// Plain text only while there is no logger to use: when loading failed,
	// and for --check, where the reader is a person at a terminal rather
	// than a log pipeline. A warning is reported even when loading failed —
	// a bad file mode found alongside a validation error is still worth
	// fixing in the same pass.
	if err != nil || *checkOnly {
		for _, warning := range warnings {
			fmt.Fprintf(stderr, "warning: %s\n", warning)
		}
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

	// Through the structured logger, and only there, so the journal carries
	// one record per warning in the same form as everything else. Printing
	// them plain as well produced every warning twice.
	for _, warning := range warnings {
		log.Warn("configuration warning", slog.String("detail", warning))
	}

	// The signal handler is installed here rather than inside serve: a
	// function that reaches for process-wide state cannot be composed, and
	// cannot be tested without sending the test binary a signal.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return serve(ctx, cfg, log)
}

// serve builds every component and runs the listeners until ctx is cancelled.
func serve(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	policies, err := policy.NewSet(cfg)
	if err != nil {
		return fmt.Errorf("prepare policies: %w", err)
	}

	// Built before the cache, because the Redis backend reports its
	// operation timings to it. The state collector is registered further
	// down, once the cache and throttle exist.
	collector, err := newMetrics(cfg, policies.Names())
	if err != nil {
		return fmt.Errorf("prepare metrics: %w", err)
	}

	var cacheObserver cache.Observer
	if collector != nil {
		cacheObserver = collector
	}

	decisionCache, keyer, closeCache, err := newCache(ctx, cfg, cacheObserver, log)
	if err != nil {
		return fmt.Errorf("prepare cache: %w", err)
	}

	defer closeCache()

	throttle, err := newThrottle(cfg.RateLimit)
	if err != nil {
		return fmt.Errorf("prepare throttle: %w", err)
	}

	if collector != nil {
		if err := collector.RegisterState(decisionCache, throttle); err != nil {
			return fmt.Errorf("register state metrics: %w", err)
		}
	}

	// A nil *metrics.Metrics would satisfy the observer interfaces and then
	// panic on the first call, so the nil case is turned into no observer at
	// all rather than a typed nil.
	var (
		ldapObserver   ldap.Observer
		serverObserver server.Observer
	)

	if collector != nil {
		ldapObserver = collector
		serverObserver = collector
	}

	directories, closeDirectories, err := auth.Directories(cfg, log, ldapObserver)
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

	// Built before the server, because a broken login template or an
	// unusable secret has to stop the process here rather than surface as a
	// failed login later.
	sessions, err := server.NewSessions(cfg.Session)
	if err != nil {
		return fmt.Errorf("prepare sessions: %w", err)
	}

	srv, err := server.New(server.Options{
		Config:        cfg.Server,
		Authenticator: authenticator,
		Sessions:      sessions,
		Cache:         decisionCache,
		Throttle:      throttle,
		LogUsername:   cfg.Logging.LogUsername,
		Logger:        log,
		Observer:      serverObserver,
	})
	if err != nil {
		return fmt.Errorf("prepare server: %w", err)
	}

	logStartup(log, cfg, policies, decisionCache)

	listeners := []func(context.Context) error{srv.Serve}

	if collector != nil {
		listeners = append(listeners, metrics.NewListener(cfg.Metrics, collector, log).Serve)
	}

	if err := runListeners(ctx, listeners); err != nil {
		return err
	}

	log.Info("stopped")

	return nil
}

// runListeners runs every listener until one fails or ctx is cancelled.
//
// The first failure brings the rest down. A service whose metrics listener
// could not bind but whose authentication listener did would look healthy and
// be unmonitored — which is worse than not starting, because the gap is
// invisible precisely in the system that would have reported it.
func runListeners(ctx context.Context, listeners []func(context.Context) error) error {
	// A derived context, so cancelling on failure does not reach back into
	// the caller's.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	failures := make(chan error, len(listeners))

	for _, listen := range listeners {
		serve := listen

		go func() { failures <- serve(ctx) }()
	}

	var first error

	for range listeners {
		err := <-failures

		if err != nil && first == nil {
			first = err

			// Bring the others down so that Serve returns and the
			// remaining receives complete.
			cancel()
		}
	}

	return first
}

// newMetrics builds the metric set, or returns nil when metrics are disabled.
func newMetrics(cfg *config.Config, policyNames []string) (*metrics.Metrics, error) {
	if !cfg.Metrics.Enabled {
		return nil, nil
	}

	// Every configured timeout becomes a histogram boundary, so that an
	// operation hitting one is visible as a bucket rather than disappearing
	// into +Inf with everything else that was slow.
	timeouts := []time.Duration{
		cfg.Server.ReadTimeout.Duration(),
		cfg.Server.WriteTimeout.Duration(),
	}

	for _, dir := range cfg.LDAP {
		timeouts = append(timeouts, dir.BindTimeout.Duration(), dir.OperationTimeout.Duration())
	}

	if cfg.Redis.Enabled {
		timeouts = append(timeouts, cfg.Redis.Timeout.Duration())
	}

	return metrics.New(metrics.Options{
		Version:  version,
		Policies: policyNames,
		Timeouts: timeouts,
	})
}

// newCache returns the decision cache, the keyer that derives its keys, and a
// function to release it.
func newCache(
	ctx context.Context,
	cfg *config.Config,
	observer cache.Observer,
	log *slog.Logger,
) (decisionCache cache.Cache, keyer *cache.Keyer, release func(), err error) {
	release = func() {}

	if !cfg.Cache.Enabled {
		return cache.Disabled{}, nil, release, nil
	}

	keyer, err = cache.NewKeyer(cfg.Cache.Pepper)
	if err != nil {
		return nil, nil, release, fmt.Errorf("cache keyer: %w", err)
	}

	if !cfg.Redis.Enabled {
		memory, err := cache.NewMemory(cfg.Cache.MaxEntries)
		if err != nil {
			return nil, nil, release, err
		}

		return memory, keyer, release, nil
	}

	shared, err := cache.NewRedis(cache.RedisOptions{
		Address:  cfg.Redis.Address,
		Database: cfg.Redis.Database,
		Password: cfg.Redis.Password,
		Timeout:  cfg.Redis.Timeout.Duration(),
		Observer: observer,
		Logger:   log,
	})
	if err != nil {
		return nil, nil, release, err
	}

	// Reported, never fatal. An unreachable shared cache costs LDAP binds
	// and nothing else, and refusing to start over it would turn a cache
	// outage into a site outage — which is the failure this whole design
	// exists to avoid.
	if err := shared.Ping(ctx); err != nil {
		log.Warn("shared cache is not reachable; authenticating against the directory directly",
			slog.String("address", cfg.Redis.Address),
			slog.String("error", err.Error()))
	}

	return shared, keyer, func() {
		if err := shared.Close(); err != nil {
			log.Debug("close shared cache", slog.String("error", err.Error()))
		}
	}, nil
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
		slog.String("build_date", buildDate),
		slog.String("go", runtime.Version()),
		slog.String("revision", revision()),
	)

	log.Info("configuration loaded",
		slog.Any("policies", policies.Names()),
		slog.String("default_policy", policies.DefaultName()),
		slog.Int("directories", len(cfg.LDAP)),
		slog.String("cache", decisionCache.Name()),
		slog.Bool("cache_shared", cfg.Redis.Enabled),
		slog.String("cache_ttl", cfg.Cache.TTL.String()),
		slog.String("negative_ttl", cfg.Cache.NegativeTTL.String()),
		slog.Bool("throttle", cfg.RateLimit.Enabled),
		slog.Bool("session", cfg.Session.Enabled),
	)

	// The two timeouts are the answer to "why am I still logged in", so they
	// belong in the journal rather than only in the configuration file.
	if cfg.Session.Enabled {
		log.Info("sessions enabled",
			slog.String("login_path", cfg.Session.LoginPath),
			slog.String("logout_path", cfg.Session.LogoutPath),
			slog.String("absolute_timeout", cfg.Session.AbsoluteTimeout.String()),
			slog.String("idle_timeout", cfg.Session.IdleTimeout.String()),
			slog.Bool("basic_auth_accepted", cfg.Session.AllowBasic),
			slog.Bool("secure_cookie", cfg.Session.SecureCookie()),
		)
	} else {
		log.Info("sessions disabled: HTTP Basic Authentication has no logout and no expiry, " +
			"so a browser stays signed in until it is closed")
	}

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
