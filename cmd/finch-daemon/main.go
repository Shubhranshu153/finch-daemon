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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/moby/moby/pkg/pidfile"
	"github.com/runfinch/finch-daemon/api/router"
	"github.com/runfinch/finch-daemon/pkg/flog"
	"github.com/runfinch/finch-daemon/version"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	// Keep this value in sync with `guestSocket` in README.md.
	defaultFinchAddr = "/run/finch.sock"
	defaultPidFile   = "/run/finch.pid"
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

func handlePidFileOptions(options *DaemonOptions) error {
	if options.PidFile != "" {
		if err := os.MkdirAll(filepath.Dir(options.PidFile), 0o755); err != nil {
			return fmt.Errorf("failed to create pidfile directory %s", err)
		}
		if err := pidfile.Write(options.PidFile, os.Getpid()); err != nil {
			return fmt.Errorf("failed to start daemon, ensure finch daemon is not running or delete %s %s", options.PidFile, err)
		}
	}
	return nil
}

func run(options *DaemonOptions) error {
	// This sets the log level of the dependencies that use logrus (e.g., containerd library).
	if options.debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	defer func() {
		if err := os.Remove(options.PidFile); err != nil {
			fmt.Errorf("failed to remove pidfile %s", options.PidFile)
		}
	}()

	if err := handlePidFileOptions(options); err != nil {
		return err
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
	conf, err := initializeConfig(debug)
	if err != nil {
		return nil, err
	}

	clientWrapper, err := createContainerdClient(conf)
	if err != nil {
		return nil, err
	}

	ncWrapper, err := createNerdctlWrapper(clientWrapper, conf)
	if err != nil {
		return nil, err
	}

	opts := createRouterOptions(conf, clientWrapper, ncWrapper, logger)
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
