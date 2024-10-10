// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/config"
	ncdefaults "github.com/containerd/nerdctl/pkg/defaults"
	toml "github.com/pelletier/go-toml/v2"
	"github.com/runfinch/finch-daemon/api/router"
	"github.com/runfinch/finch-daemon/internal/backend"
	"github.com/runfinch/finch-daemon/internal/service/builder"
	"github.com/runfinch/finch-daemon/internal/service/container"
	"github.com/runfinch/finch-daemon/internal/service/exec"
	"github.com/runfinch/finch-daemon/internal/service/image"
	"github.com/runfinch/finch-daemon/internal/service/network"
	"github.com/runfinch/finch-daemon/internal/service/system"
	"github.com/runfinch/finch-daemon/internal/service/volume"
	"github.com/runfinch/finch-daemon/pkg/archive"
	"github.com/runfinch/finch-daemon/pkg/ecc"
	"github.com/runfinch/finch-daemon/pkg/flog"
	"github.com/spf13/afero"
)

// handleNerdctlGlobalOptions gets nerdctl config value from nerdctl.toml file.
func handleNerdctlGlobalOptions(cfg *config.Config) error {
	tomlPath := getTomlPath()
	r, err := os.Open(tomlPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // File not found; this is not an error.
		}
		return err // Return other errors directly.
	}
	defer r.Close()

	dec := toml.NewDecoder(r).DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf(
			"failed to load nerdctl config from %q (Note: This is referring to `nerdctl.toml`): %w",
			tomlPath, err,
		)
	}
	return nil
}

// handleNerdctlGlobalOptionsEnvVariable configures nerdctl config values with env values.
func handleNerdctlGlobalOptionsEnvVariable(cfg *config.Config) error {
	envVars := map[string]*string{
		"CONTAINERD_ADDRESS":      &cfg.Address,
		"CONTAINERD_NAMESPACE":    &cfg.Namespace,
		"CONTAINERD_SNAPSHOTTER":  &cfg.Snapshotter,
		"CNI_PATH":                &cfg.CNIPath,
		"NETCONFPATH":             &cfg.CNINetConfPath,
		"NERDCTL_HOST_GATEWAY_IP": &cfg.HostGatewayIP,
	}

	for env, field := range envVars {
		if value, ok := os.LookupEnv(env); ok {
			*field = value
		}
	}

	if value, ok := os.LookupEnv("NERDCTL_EXPERIMENTAL"); ok {
		experimental, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Experimental = experimental
	}
	return nil
}

// getTomlPath retrieves the TOML configuration path.
func getTomlPath() string {
	if v, ok := os.LookupEnv("NERDCTL_TOML"); ok {
		return v
	}
	return ncdefaults.NerdctlTOML()
}

// initializeConfig initializes configuration from file, environment, and set default values.
func initializeConfig(debug bool) (*config.Config, error) {
	conf := config.New()

	if err := handleNerdctlGlobalOptions(conf); err != nil {
		return nil, err
	}

	if err := handleNerdctlGlobalOptionsEnvVariable(conf); err != nil {
		return nil, err
	}

	if debug {
		conf.Debug = debug
	}
	if conf.Namespace == "" || conf.Namespace == namespaces.Default {
		conf.Namespace = defaultNamespace
	}

	return conf, nil
}

// createNerdctlWrapper creates the Nerdctl wrapper and checks for the nerdctl binary.
func createNerdctlWrapper(clientWrapper *backend.ContainerdClientWrapper, conf *config.Config) (*backend.NerdctlWrapper, error) {
	// GlobalCommandOptions is actually just an alias for Config, see
	// https://github.com/containerd/nerdctl/blob/9f8655f7722d6e6851755123730436bf1a6c9995/pkg/api/types/global.go#L21
	globalOptions := (*types.GlobalCommandOptions)(conf)
	ncWrapper := backend.NewNerdctlWrapper(clientWrapper, globalOptions)
	if _, err := ncWrapper.GetNerdctlExe(); err != nil {
		return nil, fmt.Errorf("failed to find nerdctl binary: %w", err)
	}
	return ncWrapper, nil
}

// createContainerdClient creates and wraps the containerd client.
func createContainerdClient(conf *config.Config) (*backend.ContainerdClientWrapper, error) {
	client, err := containerd.New(conf.Address, containerd.WithDefaultNamespace(conf.Namespace))
	if err != nil {
		return nil, fmt.Errorf("failed to create containerd client: %w", err)
	}
	return backend.NewContainerdClientWrapper(client), nil
}

// createRouterOptions creates router options by initializing all required services.
func createRouterOptions(
	conf *config.Config,
	clientWrapper *backend.ContainerdClientWrapper,
	ncWrapper *backend.NerdctlWrapper,
	logger *flog.Logrus,
) *router.Options {
	fs := afero.NewOsFs()
	tarCreator := archive.NewTarCreator(ecc.NewExecCmdCreator(), logger)
	tarExtractor := archive.NewTarExtractor(ecc.NewExecCmdCreator(), logger)

	return &router.Options{
		Config:           conf,
		ContainerService: container.NewService(clientWrapper, ncWrapper, logger, fs, tarCreator, tarExtractor),
		ImageService:     image.NewService(clientWrapper, ncWrapper, logger),
		NetworkService:   network.NewService(clientWrapper, ncWrapper, logger),
		SystemService:    system.NewService(clientWrapper, ncWrapper, logger),
		BuilderService:   builder.NewService(clientWrapper, ncWrapper, logger, tarExtractor),
		VolumeService:    volume.NewService(ncWrapper, logger),
		ExecService:      exec.NewService(clientWrapper, logger),
		NerdctlWrapper:   ncWrapper,
	}
}
