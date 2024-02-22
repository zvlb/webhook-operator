/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/zvlb/webhook-operator/internal/cert"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// WebhookReconciler reconciles a Test object
type WebhookReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Namespace string
}

const (
	SecretName                         = "webhook-operator-tls"
	ServiceName                        = "webhook-operator-webhook-service"
	ValidatingWebhookConfigurationName = "webhook-operator-validating-webhook-cfg"
	WebhookSecretLabelValue            = "webhook"

	certificateExpirationThreshold = 3 * 24 * time.Hour
	certificateValidity            = 6 * 30 * 24 * time.Hour
)

// SetupWithManager sets up the controller with the Manager.
func (r *WebhookReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Add event with TLS secret to Reconcile
	enqueueFn := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Namespace: r.Namespace,
					Name:      SecretName,
				},
			},
		}
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}, NamesMatchingPredicate(SecretName)).
		Watches(&admissionregistrationv1.ValidatingWebhookConfiguration{}, enqueueFn, NamesMatchingPredicate(ValidatingWebhookConfigurationName)).
		Complete(r)
}

func (r *WebhookReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.Log.WithValues("controller", "webhook")
	log.Info("Reconciling Webhook")

	certSecret := &corev1.Secret{}
	if err := r.Client.Get(ctx, req.NamespacedName, certSecret); err != nil {
		return reconcile.Result{}, err
	}

	if err := r.ReconcileCertificates(ctx, certSecret); err != nil {
		return reconcile.Result{}, err
	}

	// Check certificate expiried time
	certificate, err := cert.GetCertificateFromBytes(certSecret.Data[corev1.TLSCertKey])
	if err != nil {
		return reconcile.Result{}, err
	}

	now := time.Now()
	requeueTime := certificate.NotAfter.Add(-(certificateExpirationThreshold - 1*time.Second))
	rq := requeueTime.Sub(now)

	log.Info("Reconciliation completed, processing back in " + rq.String())

	return reconcile.Result{Requeue: true, RequeueAfter: rq}, nil
}

func (r *WebhookReconciler) ReconcileCertificates(ctx context.Context, certSecret *corev1.Secret) error {

	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: certSecret.Namespace, Name: certSecret.Name}, certSecret); err != nil {
		return err
	}

	// If need create of update certificate for webhook - do it
	if r.shouldUpdateCertificate(certSecret) {
		ca, err := cert.GenerateCertificateAuthority()
		if err != nil {
			return err
		}

		opts := cert.NewCertOpts(time.Now().Add(certificateValidity), fmt.Sprintf("%s.%s.svc", ServiceName, r.Namespace))

		crt, key, err := ca.GenerateCertificate(opts)
		if err != nil {
			return err
		}

		caCrt, _ := ca.CACertificatePem()

		certSecret.Data = map[string][]byte{
			corev1.TLSCertKey:              crt.Bytes(),
			corev1.TLSPrivateKeyKey:        key.Bytes(),
			corev1.ServiceAccountRootCAKey: caCrt.Bytes(),
		}

		t := &corev1.Secret{ObjectMeta: certSecret.ObjectMeta}

		_, err = controllerutil.CreateOrUpdate(ctx, r.Client, t, func() error {
			t.Data = certSecret.Data

			return nil
		})
		if err != nil {
			return err
		}
	}

	caBundle, ok := certSecret.Data[corev1.ServiceAccountRootCAKey]
	if !ok {
		return fmt.Errorf("missing %s field in %s secret", corev1.ServiceAccountRootCAKey, SecretName)
	}

	return r.updateValidatingWebhookConfiguration(ctx, caBundle)
}

// shouldUpdateCertificate checks whether it is necessary to update or create a certificate
func (r *WebhookReconciler) shouldUpdateCertificate(secret *corev1.Secret) bool {
	if _, ok := secret.Data[corev1.ServiceAccountRootCAKey]; !ok {
		return true
	}

	certificate, key, err := cert.GetCertificateWithPrivateKeyFromBytes(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return true
	}

	if err := cert.ValidateCertificate(certificate, key, certificateExpirationThreshold); err != nil {
		return true
	}

	return false
}

func (r *WebhookReconciler) updateValidatingWebhookConfiguration(ctx context.Context, caBundle []byte) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() (err error) {
		vw := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		err = r.Get(ctx, types.NamespacedName{Name: ValidatingWebhookConfigurationName}, vw)
		if err != nil {
			return err
		}
		for i, w := range vw.Webhooks {
			// Updating CABundle only in case of an internal service reference
			if w.ClientConfig.Service != nil {
				vw.Webhooks[i].ClientConfig.CABundle = caBundle
			}
		}

		return r.Update(ctx, vw, &client.UpdateOptions{})
	})
}
