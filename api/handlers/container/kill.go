// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"net/http"
	"os"

	"github.com/containerd/containerd/v2/pkg/namespaces"
	ncTypes "github.com/containerd/nerdctl/v2/pkg/api/types"
	"github.com/gorilla/mux"

	"github.com/runfinch/finch-daemon/api/response"
	"github.com/runfinch/finch-daemon/pkg/errdefs"
)

// kill creates a new kill instance.
func (h *handler) kill(w http.ResponseWriter, r *http.Request) {
	cid, ok := mux.Vars(r)["id"]
	if !ok || cid == "" {
		response.JSON(w, http.StatusBadRequest, response.NewErrorFromMsg("must specify a container ID"))
		return
	}

	ctx := namespaces.WithNamespace(r.Context(), h.Config.Namespace)

	signal := r.URL.Query().Get("signal")
	if signal == "" {
		signal = "SIGKILL"
	}

	devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0600)
	if err != nil {
		response.JSON(w, http.StatusBadRequest, response.NewErrorFromMsg("failed to open /dev/null"))
		return
	}
	defer devNull.Close()

	globalOpt := ncTypes.GlobalCommandOptions(*h.Config)
	options := ncTypes.ContainerKillOptions{
		GOptions:   globalOpt,
		KillSignal: signal,
		Stdout:     devNull,
		Stderr:     devNull,
	}

	err = h.service.Kill(ctx, cid, options)
	if err != nil {
		var code int
		switch {
		case errdefs.IsNotFound(err):
			code = http.StatusNotFound
		case errdefs.IsConflict(err):
			code = http.StatusConflict
		default:
			code = http.StatusInternalServerError
		}
		response.JSON(w, code, response.NewError(err))
		return
	}

	response.Status(w, http.StatusNoContent)
}
