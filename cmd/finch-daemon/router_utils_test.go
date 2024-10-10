// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/containerd/nerdctl/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleNerdctlGlobalOptionsEnvVariable(t *testing.T) {
	cfg := &config.Config{}

	// Set mock environment variables.
	os.Setenv("CONTAINERD_ADDRESS", "test_address")
	defer os.Unsetenv("CONTAINERD_ADDRESS")
	os.Setenv("CONTAINERD_NAMESPACE", "test_namespace")
	defer os.Unsetenv("CONTAINERD_NAMESPACE")
	os.Setenv("NERDCTL_EXPERIMENTAL", "true")
	defer os.Unsetenv("NERDCTL_EXPERIMENTAL")

	err := handleNerdctlGlobalOptionsEnvVariable(cfg)
	assert.NoError(t, err, "Valid environment variables should not cause an error.")
	assert.Equal(t, "test_address", cfg.Address)
	assert.Equal(t, "test_namespace", cfg.Namespace)
	assert.True(t, cfg.Experimental)
}

func TestHandleNerdctlGlobalOptionsEnvVariable_InvalidBool(t *testing.T) {
	cfg := &config.Config{}

	os.Setenv("NERDCTL_EXPERIMENTAL", "invalid")
	defer os.Unsetenv("NERDCTL_EXPERIMENTAL")

	err := handleNerdctlGlobalOptionsEnvVariable(cfg)
	assert.Error(t, err, "Invalid boolean environment variable should cause an error.")
}
func TestInitializeConfig(t *testing.T) {
	os.Setenv("NERDCTL_TOML", "/non/existing/path/nerdctl.toml")
	os.Setenv("CONTAINERD_NAMESPACE", "test_namespace")
	defer os.Unsetenv("CONTAINERD_NAMESPACE")
	defer os.Unsetenv("NERDCTL_TOML")

	cfg, err := initializeConfig(true)
	require.NoError(t, err, "Initialization should succeed.")

	assert.True(t, cfg.Debug, "Debug mode should be enabled.")
	assert.Equal(t, "test_namespace", cfg.Namespace, "Namespace should be set from environment variable.")
}

func TestHandleNerdctlGlobalOptions_FileNotFound(t *testing.T) {
	cfg := &config.Config{}
	os.Setenv("NERDCTL_TOML", "/non/existing/path/nerdctl.toml")
	defer os.Unsetenv("NERDCTL_TOML")

	err := handleNerdctlGlobalOptions(cfg)
	assert.NoError(t, err, "File not found should not cause an error.")
}

func TestHandleNerdctlGlobalOptions_InvalidTOML(t *testing.T) {
	cfg := &config.Config{}

	tmpFile, err := os.CreateTemp("/tmp", "invalid.toml")
	os.Setenv("NERDCTL_TOML", tmpFile.Name())
	defer os.Unsetenv("NERDCTL_TOML")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, _ = tmpFile.WriteString("invalid_toml")

	err = handleNerdctlGlobalOptions(cfg)
	assert.Error(t, err, "Invalid TOML should return an error.")
	assert.True(t, strings.Contains(err.Error(), "failed to load nerdctl config"))
}

func TestHandleNerdctlGlobalOptions_ValidTOML(t *testing.T) {
	cfg := &config.Config{}

	// Create a temporary valid TOML file
	tmpFile, err := os.CreateTemp("", "valid.toml")
	os.Setenv("NERDCTL_TOML", tmpFile.Name())
	defer os.Unsetenv("NERDCTL_TOML")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, _ = tmpFile.WriteString(`
address = "test_address"
namespace = "test_namespace"
`)

	err = handleNerdctlGlobalOptions(cfg)
	assert.NoError(t, err, "Valid TOML should not cause an error.")
	assert.Equal(t, "test_address", cfg.Address)
	assert.Equal(t, "test_namespace", cfg.Namespace)
}
