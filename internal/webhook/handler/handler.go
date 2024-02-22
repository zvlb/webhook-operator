package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	webhookv1alpha1 "github.com/zvlb/webhook-operator/api/v1alpha1"
)

type Handler struct{}

func (h *Handler) Handle(ctx context.Context, req admission.Request) admission.Response {
	// Check resource Group
	if req.AdmissionRequest.Kind.Group != "webhook.zvlb.github.io" {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("invalid group: %s", req.AdmissionRequest.Kind.Group))
	}

	switch res := req.AdmissionRequest.Kind.Kind; res {
	case "Test":
		object := &webhookv1alpha1.Test{}
		if err := json.Unmarshal(req.Object.Raw, object); err != nil {
			return admission.Errored(http.StatusInternalServerError, fmt.Errorf("%v. %w", "cannot unmarshal", err))
		}
		if err := object.Validate(); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
	}

	return admission.Allowed("")
}
