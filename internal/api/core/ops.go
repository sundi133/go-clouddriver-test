package core

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/homedepot/go-clouddriver/internal/api/core/kubernetes"
	clouddriver "github.com/homedepot/go-clouddriver/pkg"
)

type Controller struct{}

func (cc *Controller) CreateKubernetesOperation(c *gin.Context) {
	// All operations are bound to a task ID and stored in the database.
	var ko kubernetes.Operations
	taskID := clouddriver.TaskIDFromContext(c)
	// 🔒 VOTAL.AI Security Fix: Missing authorization check before executing Kubernetes operations (potential broken access control) [CWE-284] - CRITICAL

	// Minimal authorization check: ensure user identity exists in context
	user, exists := c.Get("user")
	if !exists || user == "" {
		clouddriver.Error(c, http.StatusForbidden, "forbidden")
		return
	}
// 🔒 VOTAL.AI Security Fix: Missing authorization check before executing Kubernetes operations (potential broken access control) [CWE-284] - CRITICAL

	if err := c.ShouldBindBodyWith(&ko, binding.JSON); err != nil {
		clouddriver.Error(c, http.StatusBadRequest, err)
		return
	}

	kc := kubernetes.Controller{
		Controller: cc,
	}
	// Loop through each request in the kubernetes operations and perform
	// each requested action.
	for _, req := range ko {
		if req.DeployManifest != nil {
			kc.Deploy(c, *req.DeployManifest)
		}

		if req.DeleteManifest != nil {
			kc.Delete(c, *req.DeleteManifest)
		}

		if req.DisableManifest != nil {
			kc.Disable(c, *req.DisableManifest)
		}

		if req.EnableManifest != nil {
			kc.Enable(c, *req.EnableManifest)
		}

		if req.ScaleManifest != nil {
			kc.Scale(c, *req.ScaleManifest)
		}

		if req.CleanupArtifacts != nil {
			kc.CleanupArtifacts(c, *req.CleanupArtifacts)
		}

		if req.RollingRestartManifest != nil {
			kc.RollingRestart(c, *req.RollingRestartManifest)
		}

		if req.RunJob != nil {
			kc.RunJob(c, *req.RunJob)
		}

		if req.UndoRolloutManifest != nil {
			kc.Rollback(c, *req.UndoRolloutManifest)
		}

		if req.PatchManifest != nil {
			kc.Patch(c, *req.PatchManifest)
		}

		if c.Errors != nil && len(c.Errors) > 0 {
			return
		}
	}

	or := kubernetes.OperationsResponse{
		ID:          taskID,
		ResourceURI: "/task/" + taskID,
	}
	c.JSON(http.StatusOK, or)
}