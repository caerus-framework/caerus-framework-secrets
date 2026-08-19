package cf_secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cf "github.com/caerus-framework/caerus-framework"
	cf_configuration "github.com/caerus-framework/caerus-framework-configuration"
	cf_logs "github.com/caerus-framework/caerus-framework-logs"
	cf_observability "github.com/caerus-framework/caerus-framework-observability"
)

const (
	// ComponentName is the framework registry identity. Peers list this in
	// GetDependencies. It is not the configuration source name (that comes
	// from WithConfigSource).
	ComponentName = "secrets"
)

// ComponentStage is the bootstrap secrets stage (after logs, configuration,
// observability; before data). The framework already registers this stage;
// this component is still declared in main — it is not auto-inserted like logs.
const ComponentStage = cf.SecretsStage

// Option configures the secrets component at construction time.
type Option func(*options)

type options struct {
	loaded             *SecretsConfig
	configSource       string
	configPath         string
	srcEnvPrefix       string
	srcFormat          cf_configuration.Format
	srcFormatSet       bool
	logger             *slog.Logger
	loggerSet          bool
	name               string
	degradedMode       bool
	healthWhenDegraded string
}

// SourceOption configures the self-registered configuration source created by
// WithConfigSource.
type SourceOption func(*sourceOptions)

type sourceOptions struct {
	envPrefix string
	format    cf_configuration.Format
	formatSet bool
}

// WithSourceEnvPrefix sets the environment overlay prefix for the source
// (default: the uppercase source name with "-" replaced by "_", plus "_").
// An empty prefix disables env overlay.
func WithSourceEnvPrefix(prefix string) SourceOption {
	return func(o *sourceOptions) { o.envPrefix = prefix }
}

// WithSourceFormat forces the file format instead of inferring it from the
// path extension.
func WithSourceFormat(f cf_configuration.Format) SourceOption {
	return func(o *sourceOptions) { o.format = f; o.formatSet = true }
}

func defaultSourceEnvPrefix(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
}

// WithConfig sets a static configuration snapshot (tests, embedded use).
func WithConfig(cfg SecretsConfig) Option {
	return func(o *options) { o.loaded = &cfg }
}

// WithConfigSource binds this component to a named configuration source and
// registers that source with the configuration component during argv
// absorption.
//
//	cf_secrets.New(cf_secrets.WithConfigSource("secrets", "config/secrets.json"))
func WithConfigSource(name, path string, opts ...SourceOption) Option {
	return func(o *options) {
		so := sourceOptions{envPrefix: defaultSourceEnvPrefix(name)}
		for _, opt := range opts {
			opt(&so)
		}
		o.configSource = name
		o.configPath = path
		o.srcEnvPrefix = so.envPrefix
		o.srcFormat = so.format
		o.srcFormatSet = so.formatSet
	}
}

// WithLogger overrides the framework logger (tests / embedded).
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger; o.loggerSet = true }
}

// WithName sets a custom component name (multiple secrets instances).
func WithName(name string) Option {
	return func(o *options) { o.name = name }
}

// WithDegradedMode lets Init succeed when a provider ping fails.
func WithDegradedMode() Option {
	return func(o *options) { o.degradedMode = true }
}

// CFSecrets is the secrets chassis: named providers, one Get API.
type CFSecrets struct {
	mu sync.RWMutex

	configSource string
	configPath   string
	srcEnvPrefix string
	srcFormat    cf_configuration.Format
	srcFormatSet bool

	logger    *slog.Logger
	loggerSet bool
	logsSub   *cf_logs.Subscription
	fw        *cf.CaerusFramework
	name      string

	cfg                SecretsConfig
	degradedMode       bool
	healthWhenDegraded string

	drivers map[string]driver
	ready   atomic.Bool

	gets         atomic.Int64
	getErrors    atomic.Int64
	pingFailures atomic.Int64
	degradedUses atomic.Int64
	unhealthy    atomic.Bool
}

// New constructs the component. Providers are opened at Init.
func New(opts ...Option) *CFSecrets {
	o := options{
		logger:             slog.Default(),
		healthWhenDegraded: "not_ready",
	}
	for _, opt := range opts {
		opt(&o)
	}
	c := &CFSecrets{
		configSource:       o.configSource,
		configPath:         o.configPath,
		srcEnvPrefix:       o.srcEnvPrefix,
		srcFormat:          o.srcFormat,
		srcFormatSet:       o.srcFormatSet,
		logger:             o.logger,
		loggerSet:          o.loggerSet,
		name:               o.name,
		degradedMode:       o.degradedMode,
		healthWhenDegraded: o.healthWhenDegraded,
		drivers:            map[string]driver{},
	}
	if o.loaded != nil {
		c.cfg = *o.loaded
		if o.loaded.DegradedMode != nil {
			c.degradedMode = *o.loaded.DegradedMode
		}
		if o.loaded.HealthWhenDegraded != "" {
			c.healthWhenDegraded = o.loaded.HealthWhenDegraded
		}
	}
	return c
}

// Name implements cf.CaerusComponent.
func (c *CFSecrets) Name() string {
	if c.name != "" {
		return c.name
	}
	return ComponentName
}

// GetInitOrderStage implements cf.CaerusComponent.
func (c *CFSecrets) GetInitOrderStage() cf.Stage { return ComponentStage }

// GetDependencies implements cf.Dependencies.
func (c *CFSecrets) GetDependencies() []string {
	deps := []string{cf_logs.ComponentName}
	if c.configSource != "" {
		deps = append(deps, cf_configuration.ComponentName)
	}
	return deps
}

// Init opens every configured provider and pings it.
func (c *CFSecrets) Init(ctx context.Context, fw *cf.CaerusFramework) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.fw = fw
	if !c.loggerSet {
		if logs, ok := cf.Get[*cf_logs.Logs](fw); ok {
			c.logsSub = logs.OnReconfigureFor(c.Name(), func(l *slog.Logger) { c.logger = l })
		}
	}

	if c.configSource != "" {
		cfg, err := c.loadConfig()
		if err != nil {
			return err
		}
		c.cfg = cfg
		if cfg.DegradedMode != nil {
			c.degradedMode = *cfg.DegradedMode
		}
		if cfg.HealthWhenDegraded != "" {
			c.healthWhenDegraded = cfg.HealthWhenDegraded
		}
	}

	if err := c.cfg.validate(); err != nil {
		return fmt.Errorf("cf_secrets: %w", err)
	}

	if err := c.rebuildDriversLocked(ctx); err != nil {
		return err
	}
	c.ready.Store(true)
	c.logger.Info("cf_secrets: initialized", "providers", providerNames(c.drivers), "degraded_mode", c.degradedMode)
	return nil
}

func (c *CFSecrets) loadConfig() (SecretsConfig, error) {
	conf, ok := cf.Get[*cf_configuration.Configuration](c.fw)
	if !ok {
		return SecretsConfig{}, errors.New("cf_secrets: configuration component not registered")
	}
	loaded, err := cf_configuration.Lookup[SecretsConfig](conf, c.configSource)
	if err != nil {
		return SecretsConfig{}, fmt.Errorf("cf_secrets: %w", err)
	}
	return *loaded, nil
}

func (c *CFSecrets) rebuildDriversLocked(ctx context.Context) error {
	next := make(map[string]driver, len(c.cfg.Providers))
	var pingErrs []string
	for name, p := range c.cfg.Providers {
		d, err := buildDriver(ctx, p)
		if err != nil {
			closeDrivers(next)
			return fmt.Errorf("cf_secrets: provider %q: %w", name, err)
		}
		pingCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutOrDefault(p.TimeoutSec)*float64(time.Second)))
		err = d.ping(pingCtx)
		cancel()
		if err != nil {
			c.pingFailures.Add(1)
			pingErrs = append(pingErrs, name+": "+err.Error())
			if !c.degradedMode {
				d.close()
				closeDrivers(next)
				return fmt.Errorf("cf_secrets: provider %q ping: %w", name, err)
			}
			c.degradedUses.Add(1)
			c.logger.Error("cf_secrets: DegradedMode — provider ping failed; Init continues",
				"provider", name, "kind", d.kind(), "err", err,
				"health_when_degraded", c.healthWhenDegraded,
			)
		}
		next[name] = d
	}
	old := c.drivers
	c.drivers = next
	closeDrivers(old)
	c.unhealthy.Store(len(pingErrs) > 0)
	return nil
}

func buildDriver(ctx context.Context, p ProviderConfig) (driver, error) {
	kind, err := normalizeKind(p.Kind)
	if err != nil {
		return nil, err
	}
	switch kind {
	case kindVault, kindOpenBao:
		return newVaultDriver(kind, p)
	case kindAWS:
		return newAWSDriver(ctx, p)
	case kindGCP:
		return newGCPDriver(ctx, p)
	case kindFile:
		return newFileDriver(p)
	default:
		return nil, fmt.Errorf("unknown kind %q", kind)
	}
}

func closeDrivers(m map[string]driver) {
	for _, d := range m {
		if d != nil {
			_ = d.close()
		}
	}
}

func providerNames(m map[string]driver) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	return out
}

// Get fetches a secret from the named provider. The name is the map key in
// config (e.g. "openbao"), not the kind. Callers must not switch on kind.
func (c *CFSecrets) Get(ctx context.Context, provider string, ref Ref) ([]byte, error) {
	if err := ref.validate(); err != nil {
		c.getErrors.Add(1)
		return nil, fmt.Errorf("cf_secrets: %w", err)
	}
	c.mu.RLock()
	d, ok := c.drivers[provider]
	ready := c.ready.Load()
	c.mu.RUnlock()
	if !ready {
		c.getErrors.Add(1)
		return nil, errors.New("cf_secrets: not initialized")
	}
	if !ok {
		c.getErrors.Add(1)
		return nil, fmt.Errorf("cf_secrets: unknown provider %q", provider)
	}
	c.gets.Add(1)
	b, err := d.get(ctx, ref)
	if err != nil {
		c.getErrors.Add(1)
		return nil, fmt.Errorf("cf_secrets: provider %q: %w", provider, err)
	}
	return b, nil
}

// GetString is Get decoded as text (not trimmed — callers own whitespace).
func (c *CFSecrets) GetString(ctx context.Context, provider string, ref Ref) (string, error) {
	b, err := c.Get(ctx, provider, ref)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// OnConfigReload implements cf.ConfigReloader. Failed rebuild keeps last-good
// drivers.
func (c *CFSecrets) OnConfigReload(source string, cfg any) {
	if source != c.configSource {
		return
	}
	typed, ok := cfg.(*SecretsConfig)
	if !ok || typed == nil {
		c.logger.Error("cf_secrets: config reload rejected", "source", source)
		return
	}
	if err := typed.validate(); err != nil {
		c.logger.Error("cf_secrets: config reload rejected", "err", err)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ready.Load() {
		return
	}
	prev := c.cfg
	c.cfg = *typed
	if typed.DegradedMode != nil {
		c.degradedMode = *typed.DegradedMode
	}
	if typed.HealthWhenDegraded != "" {
		c.healthWhenDegraded = typed.HealthWhenDegraded
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.rebuildDriversLocked(ctx); err != nil {
		c.cfg = prev
		c.logger.Error("cf_secrets: config reload failed; keeping previous providers", "err", err)
		return
	}
	c.logger.Info("cf_secrets: providers rebuilt after config reload", "providers", providerNames(c.drivers))
}

// RegisterConfigSources implements cf.ConfigSourceRegistrar.
func (c *CFSecrets) RegisterConfigSources(conf any) error {
	cfg, ok := conf.(*cf_configuration.Configuration)
	if !ok {
		return fmt.Errorf("cf_secrets: RegisterConfigSources: expected configuration component, got %T", conf)
	}
	if c.configSource == "" {
		return nil
	}
	format := c.srcFormat
	if !c.srcFormatSet {
		if p := strings.ToLower(c.configPath); strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
			format = cf_configuration.FormatYAML
		} else {
			format = cf_configuration.FormatJSON
		}
	}
	return cf_configuration.AddSource(cfg, cf_configuration.Source[SecretsConfig]{
		Name:      c.configSource,
		Path:      c.configPath,
		Format:    format,
		Owner:     c.Name(),
		EnvPrefix: c.srcEnvPrefix,
	})
}

// Shutdown closes provider clients.
func (c *CFSecrets) Shutdown(ctx context.Context) error {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logsSub != nil {
		c.logsSub.Unsubscribe()
		c.logsSub = nil
	}
	c.ready.Store(false)
	closeDrivers(c.drivers)
	c.drivers = map[string]driver{}
	return nil
}

// Health implements cf.HealthProvider. Unhealthy before Init, after Shutdown,
// and when a provider ping last failed (unless health_when_degraded=ready).
func (c *CFSecrets) Health(ctx context.Context) error {
	if !c.ready.Load() {
		return errors.New("cf_secrets: not initialized")
	}
	c.mu.RLock()
	drivers := make([]driver, 0, len(c.drivers))
	names := make([]string, 0, len(c.drivers))
	for n, d := range c.drivers {
		names = append(names, n)
		drivers = append(drivers, d)
	}
	degradedReady := strings.EqualFold(c.healthWhenDegraded, "ready")
	c.mu.RUnlock()

	var failed []string
	for i, d := range drivers {
		if err := d.ping(ctx); err != nil {
			failed = append(failed, names[i]+": "+err.Error())
		}
	}
	if len(failed) == 0 {
		c.unhealthy.Store(false)
		return nil
	}
	c.unhealthy.Store(true)
	c.pingFailures.Add(int64(len(failed)))
	if degradedReady && c.degradedMode {
		return nil
	}
	return fmt.Errorf("cf_secrets: unhealthy providers: %s", strings.Join(failed, "; "))
}

// Metrics implements cf_observability.MetricsProvider.
func (c *CFSecrets) Metrics() []cf_observability.Metric {
	if !c.ready.Load() {
		return nil
	}
	c.mu.RLock()
	n := len(c.drivers)
	labels := map[string]string{"component": c.Name()}
	c.mu.RUnlock()
	unhealthy := 0.0
	if c.unhealthy.Load() {
		unhealthy = 1
	}
	degraded := 0.0
	if c.degradedMode {
		degraded = 1
	}
	return []cf_observability.Metric{
		{Name: "cf_secrets_info", Help: "secrets chassis; 1 while initialized.", Value: 1, Labels: labels},
		{Name: "cf_secrets_providers", Help: "Configured provider count.", Value: float64(n), Labels: labels},
		{Name: "cf_secrets_degraded_mode", Help: "1 when DegradedMode is on.", Value: degraded, Labels: labels},
		{Name: "cf_secrets_unhealthy", Help: "1 when last Health saw a failed ping.", Value: unhealthy, Labels: labels},
		{Name: "cf_secrets_gets_total", Help: "Get calls.", Value: float64(c.gets.Load()), Labels: labels, Type: cf_observability.MetricTypeCounter},
		{Name: "cf_secrets_get_errors_total", Help: "Failed Get calls.", Value: float64(c.getErrors.Load()), Labels: labels, Type: cf_observability.MetricTypeCounter},
		{Name: "cf_secrets_ping_failures_total", Help: "Provider ping failures.", Value: float64(c.pingFailures.Load()), Labels: labels, Type: cf_observability.MetricTypeCounter},
		{Name: "cf_secrets_degraded_init_total", Help: "DegradedMode ping failures at Init/reload.", Value: float64(c.degradedUses.Load()), Labels: labels, Type: cf_observability.MetricTypeCounter},
	}
}

var (
	_ cf.CaerusComponent               = (*CFSecrets)(nil)
	_ cf.Dependencies                  = (*CFSecrets)(nil)
	_ cf.HealthProvider                = (*CFSecrets)(nil)
	_ cf_observability.MetricsProvider = (*CFSecrets)(nil)
	_ cf.ConfigReloader                = (*CFSecrets)(nil)
	_ cf.ConfigSourceRegistrar         = (*CFSecrets)(nil)
)
