// Copyright 2021 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
/*
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

package controllers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/kserve/modelmesh-serving/controllers/modelmesh"

	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kserve/modelmesh-serving/pkg/mmesh"

	"github.com/go-logr/logr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	commonLabelValue   = "modelmesh-controller"
	serviceMonitorName = "modelmesh-metrics-monitor"
)

// ServiceReconciler reconciles a ServingRuntime object
type ServiceReconciler struct {
	client.Client
	Log                  logr.Logger
	Scheme               *runtime.Scheme
	ConfigProvider       *ConfigProvider
	ConfigMapName        types.NamespacedName
	ControllerDeployment types.NamespacedName

	ModelMeshService map[string]*mmesh.MMService
	ModelEventStream *mmesh.ModelMeshEventStream

	ServiceMonitorCRDExists bool
}

// +kubebuilder:rbac:groups="monitoring.coreos.com",resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	//r.Log.V(1).Info("Service reconciler called")
	//r.Log.Info("in servicecontroller Reconcile 1 ===========", "req.NamespacedName", req.NamespacedName)
	//r.Log.Info("in servicecontroller Reconcile 2 ===========", "r.ConfigMapName", r.ConfigMapName)

	namespace := req.NamespacedName.Name
	n := &corev1.Namespace{}
	if err := r.Client.Get(ctx, req.NamespacedName, n); err != nil {
		return ctrl.Result{}, err
	}
	if !r.modelMeshEnabled(n) {
		sl := &corev1.ServiceList{}
		err := r.List(ctx, sl, client.HasLabels{"modelmesh-service"}, client.InNamespace(namespace))
		if err == nil {
			for i := range sl.Items {
				s := &sl.Items[i]
				if err2 := r.Delete(ctx, s); err2 != nil && err == nil {
					err = err2
				}
			}
		}
		if mms := r.ModelMeshService[namespace]; mms != nil {
			mms.Disconnect()
			delete(r.ModelMeshService, namespace)
		}
		return ctrl.Result{}, err
	}

	mms, ok := r.ModelMeshService[namespace]
	if !ok {
		mms = mmesh.NewMMService(namespace)
		r.ModelMeshService[namespace] = mms
	}

	cfg := r.ConfigProvider.GetConfig()
	tlsConfig, err := r.tlsConfigFromSecret(ctx, cfg.TLS.SecretName, namespace)
	if err != nil {
		return RequeueResult, err
	}
	var metricsPort, restProxyPort uint16 = 0, 0
	if cfg.Metrics.Enabled {
		metricsPort = cfg.Metrics.Port
	}
	if cfg.RESTProxy.Enabled {
		restProxyPort = cfg.RESTProxy.Port
	}
	changed := mms.UpdateConfig(
		cfg.InferenceServiceName, cfg.InferenceServicePort,
		cfg.ModelMeshEndpoint, cfg.TLS.SecretName, tlsConfig, cfg.HeadlessService, metricsPort, restProxyPort)

	if changed && req.Name != serviceMonitorName { //TODO TBD
		err2, requeue := r.applyService(ctx, mms, n)
		if err2 != nil || requeue {
			//TODO probably shorter requeue time (immediate?) for service recreate case
			return RequeueResult, err2
		}
	}

	if err = r.ModelEventStream.UpdateWatchedService(ctx, cfg.GetEtcdSecretName(), mms.Name, namespace); err != nil {
		return RequeueResult, err
	}

	// Service Monitor reconciliation should be called towards the end of the Service Reconcile method so that
	// errors returned from here should not impact any other functions.  //TODO TBD
	if r.ServiceMonitorCRDExists {
		// Reconcile Service Monitor if the ServiceMonitor CRD exists
		err, requeue := r.ReconcileServiceMonitor(ctx, cfg.Metrics, n)
		if err != nil || requeue {
			return RequeueResult, err
		}
	}

	//r.Log.Info("in servicecontroller Reconcile 2.1 ===========", " r.ModelMeshService[ns]", len(r.ModelMeshService))
	//for k, v := range r.ModelMeshService {
	//	r.Log.Info("in servicecontroller Reconcile 2.3 ===========", "key", k)
	//	r.Log.Info("in servicecontroller Reconcile 2.3 ===========", "value", v)
	//}

	return ctrl.Result{}, nil
}

func (r *ServiceReconciler) tlsConfigFromSecret(ctx context.Context, secretName string, namespace string) (*tls.Config, error) {
	if secretName == "" {
		return nil, nil
	}
	tlsSecret := corev1.Secret{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Name:      secretName,
		Namespace: namespace}, &tlsSecret)
	if err != nil {
		r.Log.Error(err, "Unable to access TLS secret", "secretName", secretName, "namespace", namespace)
		return nil, fmt.Errorf("unable to access TLS secret '%s': %v", secretName, err)
	}
	cert, ok2 := tlsSecret.Data[modelmesh.TLSSecretCertKey]
	key, ok := tlsSecret.Data[modelmesh.TLSSecretKeyKey]
	if !ok || !ok2 {
		r.Log.Error(err, "TLS secret missing required keys", "secretName", secretName, "namespace", namespace)
		return nil, fmt.Errorf("TLS secret '%s' missing %s and/or %s",
			secretName, modelmesh.TLSSecretCertKey, modelmesh.TLSSecretKeyKey)
	}
	certificate, err := tls.X509KeyPair(cert, key)
	if err != nil {
		r.Log.Error(err, "Could not load client key pair")
		return nil, fmt.Errorf("could not load client key pair: %v", err)
	}
	certPool, _ := x509.SystemCertPool() // this returns a copy
	if certPool == nil {
		certPool = x509.NewCertPool()
	}
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		return nil, errors.New("failed to append ca certs")
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}, RootCAs: certPool}, nil
}

func (r *ServiceReconciler) applyService(ctx context.Context, mms *mmesh.MMService, n *corev1.Namespace) (error, bool) {

	//r.Log.Info("in servicecontroller applyService 1 ===========", " r.ModelMeshService[ns]", len(r.ModelMeshService))
	//r.Log.Info("in servicecontroller applyService 2 ===========", " n.GetName()", n.GetName())
	//r.Log.Info("in servicecontroller applyService 3 ===========", " r.ModelMeshService[n.GetName()]", r.ModelMeshService[n.GetName()])
	//for k, v := range r.ModelMeshService {
	//	r.Log.Info("in servicecontroller applyService 3 ===========", "key", k)
	//	r.Log.Info("in servicecontroller applyService 3 ===========", "value", v)
	//}

	namespace := n.GetName()
	serviceName := mms.Name
	exists := false

	sl := &corev1.ServiceList{}
	if err := r.List(ctx, sl, client.HasLabels{"modelmesh-service"}, client.InNamespace(namespace)); err != nil {
		return err, false
	}
	var s *corev1.Service
	for i := range sl.Items {
		ss := &sl.Items[i]
		if ss.GetName() == serviceName {
			exists = true
			s = ss
		} else if err := r.Delete(ctx, ss); err != nil {
			return err, false
		}
	}

	if !exists {
		s = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceName,
				Namespace: namespace,
			},
		}
	}

	headless := mms.Headless
	if exists && (s.Spec.ClusterIP == "None") != headless {
		r.Log.Info("Deleting/recreating Service because headlessness changed",
			"service", serviceName, "headless", headless)
		// Have to recreate since ClusterIP field is immutable
		if err := r.Delete(ctx, s); err != nil {
			return err, false
		}
		// This will trigger immediate re-reconcilation
		return nil, true
	}

	s.Labels = map[string]string{
		"modelmesh-service":            serviceName,
		"app.kubernetes.io/instance":   commonLabelValue,
		"app.kubernetes.io/managed-by": commonLabelValue,
		"app.kubernetes.io/name":       commonLabelValue,
	}
	s.Spec.Selector = map[string]string{"modelmesh-service": serviceName}
	s.Spec.Ports = []corev1.ServicePort{
		{
			Name:       "grpc",
			Port:       int32(mms.Port),
			TargetPort: intstr.FromString("grpc"),
		},
	}

	if mms.MetricsPort > 0 {
		s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{
			Name:       "prometheus",
			Port:       int32(mms.MetricsPort),
			TargetPort: intstr.FromString("prometheus"),
		})
	}

	if mms.RESTPort > 0 {
		s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{
			Name:       "http",
			Port:       int32(mms.RESTPort),
			TargetPort: intstr.FromString("http"),
		})
	}

	if err := controllerutil.SetControllerReference(n, s, r.Scheme); err != nil {
		return fmt.Errorf("Could not set owner reference: %w", err), false
	}

	var err error
	if !exists {
		if headless {
			s.Spec.ClusterIP = "None"
		}
		mms.Disconnect()

		if err = r.Create(ctx, s); err != nil {
			r.Log.Error(err, "Could not create service")
		}
	} else {
		if err = mms.Connect(); err != nil {
			r.Log.Error(err, "Error establishing model-mesh gRPC conn")
		}
		if err2 := r.Update(ctx, s); err2 != nil {
			r.Log.Error(err, "Could not update service")
			if err == nil {
				err = err2
			}
		}
	}

	return err, false
}

func (r *ServiceReconciler) ReconcileServiceMonitor(ctx context.Context, metrics PrometheusConfig, owner metav1.Object) (error, bool) {
	r.Log.V(1).Info("Applying Service Monitor")

	sm := &monitoringv1.ServiceMonitor{}
	serviceName := r.ModelMeshService[owner.GetName()].Name

	err := r.Client.Get(ctx, client.ObjectKey{Name: serviceMonitorName, Namespace: owner.GetName()}, sm)
	exists := true
	if k8serr.IsNotFound(err) {
		// Create the ServiceMonitor if not found
		exists = false
		sm.Name = serviceMonitorName
		sm.Namespace = owner.GetName()
	} else if err != nil {
		r.Log.Error(err, "Unable to access service monitor", "serviceMonitorName", serviceMonitorName)
		return nil, false
	}

	// Check if the prometheus operator support is enabled
	if metrics.DisablePrometheusOperatorSupport || !metrics.Enabled {
		r.Log.V(1).Info("Configuration parameter 'DisablePrometheusOperatorSupport' is set to true (or) Metrics is disabled", "DisablePrometheusOperatorSupport", metrics.DisablePrometheusOperatorSupport, "metrics.Enabled", metrics.Enabled)
		if exists {
			// Delete ServiceMonitor CR if already exists
			if err = r.Client.Delete(ctx, sm); err != nil {
				r.Log.Error(err, "Unable to delete service monitor", "serviceMonitorName", serviceMonitorName)
			}
		}
		return nil, false
	}

	if err = controllerutil.SetControllerReference(owner, sm, r.Scheme); err != nil {
		return fmt.Errorf("Could not set owner reference: %w", err), false
	}

	sm.ObjectMeta.Labels = map[string]string{
		"modelmesh-service":            serviceName,
		"app.kubernetes.io/instance":   commonLabelValue,
		"app.kubernetes.io/managed-by": commonLabelValue,
		"app.kubernetes.io/name":       commonLabelValue,
	}
	sm.Spec.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"modelmesh-service": serviceName}}
	sm.Spec.Endpoints = []monitoringv1.Endpoint{{
		Interval: "30s",
		Port:     "prometheus",
		Scheme:   metrics.Scheme,
		TLSConfig: &monitoringv1.TLSConfig{
			SafeTLSConfig: monitoringv1.SafeTLSConfig{InsecureSkipVerify: true}, //TODO: Update the TLSConfig to use cacert
		}},
	}

	if !exists {
		err = r.Client.Create(ctx, sm)
	} else {
		err = r.Client.Update(ctx, sm)
	}
	if err != nil {
		if k8serr.IsConflict(err) {
			// this can occur during normal operations if the Service Monitor was updated during this reconcile loop
			r.Log.Info("Could not create (or) update service monitor due to resource conflict")
			return nil, true
		}
		r.Log.Error(err, "Could not create (or) update service monitor", "serviceMonitorName", serviceMonitorName)
	}
	return err, false
}

func (r *ServiceReconciler) modelMeshEnabled(n *corev1.Namespace) bool {
	if n == nil {
		return false
	}
	if v, ok := n.Labels["modelmesh-enabled"]; ok {
		return v == "true"
	} else {
		return n.Name == r.ControllerDeployment.Namespace
	}
}

func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	builder := ctrl.NewControllerManagedBy(mgr).
		Named("ServiceReconciler").
		For(&corev1.Namespace{}).
		Owns(&corev1.Service{}).
		Watches(&source.Kind{Type: &corev1.ConfigMap{}},
			ConfigWatchHandler(r.ConfigMapName, func() []reconcile.Request {
				list := &corev1.NamespaceList{}
				if err := r.Client.List(context.TODO(), list); err != nil {
					r.Log.Error(err, "Error listing Namespaces to reconcile after config change")
					return []reconcile.Request{}
				}
				requests := make([]reconcile.Request, 0, len(list.Items))
				for i := range list.Items {
					if n := &list.Items[i]; r.modelMeshEnabled(n) {
						requests = append(requests, reconcile.Request{
							NamespacedName: types.NamespacedName{Name: n.Name, Namespace: n.Namespace},
						})
					}
				}
				return requests
			}, r.ConfigProvider, &r.Client))

	//TODO TBD
	// Enable ServiceMonitor watch if ServiceMonitorCRDExists
	if r.ServiceMonitorCRDExists {
		builder.Watches(&source.Kind{Type: &monitoringv1.ServiceMonitor{}},
			handler.EnqueueRequestsFromMapFunc(func(o client.Object) []reconcile.Request {
				if o.GetName() == serviceMonitorName && o.GetNamespace() == r.ControllerDeployment.Namespace {
					return []reconcile.Request{{
						NamespacedName: types.NamespacedName{Name: serviceMonitorName, Namespace: r.ConfigMapName.Namespace},
					}}
				}
				return []reconcile.Request{}
			}))
	}
	err := builder.Complete(r)
	return err
}
