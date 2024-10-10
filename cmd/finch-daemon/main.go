// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/config"
	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/moby/moby/pkg/pidfile"
	"github.com/pelletier/go-toml/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	ncdefaults "github.com/containerd/nerdctl/pkg/defaults"
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
	"github.com/runfinch/finch-daemon/version"
)

const (
	// Keep this value in sync with `guestSocket` in README.md.
	defaultFinchAddr = "/run/finch.sock"
	defaultPidFile   = "/var/run/finch.pid"
)

type DaemonOptions struct {
	debug       bool
	socketAddr  string
	socketOwner int
	PidFile     string
}

var options = new(DaemonOptions)

func main() {
	rootCmd := &cobra.Command{
		Use:          "finch-daemon",
		Short:        "Finch daemon with a Docker-compatible API",
		Version:      strings.TrimPrefix(version.Version, "v"),
		RunE:         runAdapter,
		SilenceUsage: true,
	}
	rootCmd.Flags().StringVar(&options.socketAddr, "socket-addr", defaultFinchAddr, "server listening Unix socket address")
	rootCmd.Flags().BoolVar(&options.debug, "debug", false, "turn on debug log level")
	rootCmd.Flags().IntVar(&options.socketOwner, "socket-owner", -1, "Uid and Gid of the server socket")
	rootCmd.Flags().StringVar(&options.PidFile, "pidfile", defaultPidFile, "Pid file location")
	if err := rootCmd.Execute(); err != nil {
		log.Printf("got error: %v", err)
		log.Fatal(err)
	}
}

func runAdapter(cmd *cobra.Command, _ []string) error {
	return run(options)
}

func run(options *DaemonOptions) error {
	// This sets the log level of the dependencies that use logrus (e.g., containerd library).
	if options.debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if options.PidFile != "" {
		if err := os.MkdirAll(filepath.Dir(options.PidFile), 0o755); err != nil {
			return fmt.Errorf("failed to create pidfile directory %s", err)
		}
		if err := pidfile.Write(options.PidFile, os.Getpid()); err != nil {
			return fmt.Errorf("failed to start daemon, ensure finch daemon is not running or delete %s %s", options.PidFile, err)
		}

		defer func() {
			if err := os.Remove(options.PidFile); err != nil {
				fmt.Errorf("failed to remove pidfile %s", options.PidFile)
			}
		}()
	}

	logger := flog.NewLogrus()
	r, err := newRouter(options.debug, logger)
	if err != nil {
		return fmt.Errorf("failed to create a router: %w", err)
	}

	serverWg := &sync.WaitGroup{}
	serverWg.Add(1)

	listener, err := net.Listen("unix", options.socketAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", options.socketAddr, err)
	}
	// TODO: Revisit this after we use systemd to manage finch-daemon.
	// Related: https://github.com/lima-vm/lima/blob/5a9bca3d09481ed7109b14f8d3f0074816731f43/examples/podman-rootful.yaml#L44
	if err := os.Chown(options.socketAddr, options.socketOwner, options.socketOwner); err != nil {
		return fmt.Errorf("failed to chown the finch-daemon socket: %w", err)
	}
	server := &http.Server{
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Minute,
	}
	handleSignal(options.socketAddr, server, logger)

	go func() {
		logger.Infof("Serving on %s...", options.socketAddr)
		defer serverWg.Done()
		// Serve will either exit with an error immediately or return
		// http.ErrServerClosed when the server is successfully closed.
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal(err)
		}
	}()

	sdNotify(daemon.SdNotifyReady, logger)
	serverWg.Wait()
	logger.Debugln("Server stopped. Exiting...")
	return nil
}

func newRouter(debug bool, logger *flog.Logrus) (http.Handler, error) {
	tomlPath := ncdefaults.NerdctlTOML()
	if v, ok := os.LookupEnv("NERDCTL_TOML"); ok {
		tomlPath = v
	}

	conf := config.New()
	if err := handleNerdctlGlobalOptions(conf, tomlPath); err != nil {
		return nil, fmt.Errorf("failed to handle nerdctl global options: %w", err)
	}

	if err := handleNerdctlGlobalOptionsEnvVariable(conf); err != nil {
		return nil, fmt.Errorf("failed to handle nerdctl global options env variable: %w", err)
	}

	conf.Debug = debug
	client, err := containerd.New(conf.Address, containerd.WithDefaultNamespace(conf.Namespace))
	if err != nil {
		return nil, fmt.Errorf("failed to create containerd client: %w", err)
	}
	clientWrapper := backend.NewContainerdClientWrapper(client)
	// GlobalCommandOptions is actually just an alias for Config, see
	// https://github.com/containerd/nerdctl/blob/9f8655f7722d6e6851755123730436bf1a6c9995/pkg/api/types/global.go#L21
	globalOptions := (*types.GlobalCommandOptions)(conf)
	ncWrapper := backend.NewNerdctlWrapper(clientWrapper, globalOptions)
	if _, err = ncWrapper.GetNerdctlExe(); err != nil {
		return nil, fmt.Errorf("failed to find nerdctl binary: %w", err)
	}
	fs := afero.NewOsFs()
	execCmdCreator := ecc.NewExecCmdCreator()
	tarCreator := archive.NewTarCreator(execCmdCreator, logger)
	tarExtractor := archive.NewTarExtractor(execCmdCreator, logger)
	opts := &router.Options{
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
	return router.New(opts), nil
}

func handleSignal(socket string, server *http.Server, logger *flog.Logrus) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		switch sig {
		case os.Interrupt:
			sdNotify(daemon.SdNotifyStopping, logger)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				log.Fatal(err)
			}
		case syscall.SIGTERM:
			sdNotify(daemon.SdNotifyStopping, logger)
			if err := server.Close(); err != nil {
				log.Fatal(err)
			}
			os.Remove(socket)
		}
	}()
}

func sdNotify(state string, logger *flog.Logrus) {
	// (false, nil) - notification not supported (i.e. NOTIFY_SOCKET is unset)
	// (false, err) - notification supported, but failure happened (e.g. error connecting to NOTIFY_SOCKET or while sending data)
	// (true, nil) - notification supported, data has been sent
	notified, err := daemon.SdNotify(false, state)
	logger.Debugf("systemd-notify result: (signaled %t), (err: %v)", notified, err)
}

func handleNerdctlGlobalOptions(cfg *config.Config, tomlPath string) error {
	if r, err := os.Open(tomlPath); err == nil {
		defer r.Close()
		dec := toml.NewDecoder(r).DisallowUnknownFields() // set Strict to detect typo
		if err := dec.Decode(cfg); err != nil {
			return fmt.Errorf("failed to load nerdctl config (not daemon config) from %q (Hint: don't mix up daemon's `config.toml` with `nerdctl.toml`): %w", tomlPath, err)
		}
	} else {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// env variables override the config file settings
func handleNerdctlGlobalOptionsEnvVariable(cfg *config.Config) error {

	if env, ok := os.LookupEnv("CONTAINERD_ADDRESS"); ok {
		cfg.Address = env
	}
	if env, ok := os.LookupEnv("CONTAINERD_NAMESPACE"); ok {
		cfg.Namespace = env
	}
	if env, ok := os.LookupEnv("CONTAINERD_SNAPSHOTTER"); ok {
		cfg.Snapshotter = env
	}
	if env, ok := os.LookupEnv("CNI_PATH"); ok {
		cfg.CNIPath = env
	}
	if env, ok := os.LookupEnv("NETCONFPATH"); ok {
		cfg.CNINetConfPath = env
	}
	if env, ok := os.LookupEnv("NERDCTL_EXPERIMENTAL"); ok {
		var err error
		var envV bool
		envV, err = strconv.ParseBool(env)
		if err != nil {
			return err
		}
		cfg.Experimental = envV
	}
	if env, ok := os.LookupEnv("NERDCTL_HOST_GATEWAY_IP"); ok {
		cfg.HostGatewayIP = env
	}
	return nil

}
