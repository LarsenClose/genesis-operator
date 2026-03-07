package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/larsenclose/genesis/internal/bridge"
	genesisv1alpha1 "github.com/larsenclose/genesis/pkg/api/v1alpha1"
)

const (
	rotationFinalizerName = "genesis.io/rotation-finalizer"
)

// RotationExecutor abstracts the cryptographic key rotation flow.
// Production uses the Rust bridge (BridgeRotationExecutor); tests use
// a mock implementation.
type RotationExecutor interface {
	Rotate(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap, secretName, secretNamespace, secretKey string) (*bridge.PublicArtifacts, error)
}

// BridgeRotationExecutor implements RotationExecutor using the Rust bridge.
// The full rotation flow runs entirely in Rust memory: decrypt existing
// envelope, inject current secret (to reach Active), begin rotation,
// complete rotation (new keypair + re-encrypt + inject new secret).
type BridgeRotationExecutor struct{}

// Rotate implements RotationExecutor via the Rust bridge path.
func (e *BridgeRotationExecutor) Rotate(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap, secretName, secretNamespace, secretKey string) (*bridge.PublicArtifacts, error) {
	// 1. Build KMS config JSON from the GenesisBootstrap's envelope spec
	kmsConfigJSON, err := bridge.BuildKmsConfigJSON(&bootstrap.Spec.Envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to build KMS config: %w", err)
	}

	// 2. Create bridge handle
	handle, err := bridge.New(kmsConfigJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge handle: %w", err)
	}
	defer handle.Free()

	// 3. Decode ciphertext and load existing config (public key + ciphertext)
	ciphertext, err := base64.StdEncoding.DecodeString(bootstrap.Spec.Envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	if err := handle.Load(bootstrap.Spec.Envelope.PublicKey, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to load envelope: %w", err)
	}

	// 4. Begin bootstrap to reach Bootstrapping state (decrypts existing envelope)
	if err := handle.BeginBootstrap(kmsConfigJSON); err != nil {
		return nil, fmt.Errorf("failed to begin bootstrap: %w", err)
	}

	// 5. Inject existing secret to reach Active state
	if err := handle.InjectSecret(secretName, secretNamespace, secretKey, bootstrap.Name, bootstrap.Namespace); err != nil {
		return nil, fmt.Errorf("failed to inject secret: %w", err)
	}

	// 6. Begin rotation (Active -> Rotating)
	if err := handle.BeginRotation(); err != nil {
		return nil, fmt.Errorf("failed to begin rotation: %w", err)
	}

	// 7. Complete rotation -- generates new keypair, KMS encrypts, injects new key
	// If CompleteRotation fails, abort the rotation to clean up state machine
	// and emit a proper audit event before returning the error.
	artifacts, err := handle.CompleteRotation(kmsConfigJSON, secretName, secretNamespace, secretKey, bootstrap.Name, bootstrap.Namespace)
	if err != nil {
		if abortErr := handle.AbortRotation(); abortErr != nil {
			log.FromContext(ctx).Error(abortErr, "failed to abort rotation after CompleteRotation error")
		}
		return nil, fmt.Errorf("failed to complete rotation: %w", err)
	}

	return artifacts, nil
}

// GenesisRotationPolicyReconciler reconciles a GenesisRotationPolicy object
type GenesisRotationPolicyReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Recorder         record.EventRecorder
	RotationExecutor RotationExecutor // If nil, uses BridgeRotationExecutor
}

// GetRotationExecutor returns the configured rotation executor or the default.
func (r *GenesisRotationPolicyReconciler) GetRotationExecutor() RotationExecutor {
	if r.RotationExecutor != nil {
		return r.RotationExecutor
	}
	return &BridgeRotationExecutor{}
}

// +kubebuilder:rbac:groups=genesis.io,resources=genesisrotationpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=genesis.io,resources=genesisrotationpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=genesis.io,resources=genesisrotationpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=genesis.io,resources=genesisbootstraps,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles the reconciliation loop for GenesisRotationPolicy resources
func (r *GenesisRotationPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling GenesisRotationPolicy")

	// Fetch the GenesisRotationPolicy instance
	policy := &genesisv1alpha1.GenesisRotationPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("GenesisRotationPolicy not found, likely deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get GenesisRotationPolicy")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !policy.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, policy)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(policy, rotationFinalizerName) {
		controllerutil.AddFinalizer(policy, rotationFinalizerName)
		if err := r.Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Check if rotation is suspended
	if policy.Spec.Suspend {
		logger.Info("Rotation policy is suspended")
		r.setCondition(policy, genesisv1alpha1.ConditionTypeRotationReady, metav1.ConditionFalse,
			genesisv1alpha1.ReasonRotationSuspended, "Rotation is suspended")
		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Parse the rotation interval
	interval, err := time.ParseDuration(policy.Spec.Schedule.Interval)
	if err != nil {
		logger.Error(err, "Invalid rotation interval", "interval", policy.Spec.Schedule.Interval)
		r.setCondition(policy, genesisv1alpha1.ConditionTypeRotationReady, metav1.ConditionFalse,
			genesisv1alpha1.ReasonRotationFailed, fmt.Sprintf("Invalid interval: %v", err))
		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Check if the source secret exists
	sourceSecret := &corev1.Secret{}
	sourceKey := types.NamespacedName{
		Name:      policy.Spec.Source.Name,
		Namespace: policy.Spec.Source.Namespace,
	}
	if err := r.Get(ctx, sourceKey, sourceSecret); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Source secret not found", "name", sourceKey.Name, "namespace", sourceKey.Namespace)
			r.setCondition(policy, genesisv1alpha1.ConditionTypeRotationReady, metav1.ConditionFalse,
				genesisv1alpha1.ReasonRotationFailed, "Source secret not found")
			if err := r.Status().Update(ctx, policy); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		return ctrl.Result{}, err
	}

	// Calculate next rotation time
	var nextRotation time.Time
	if policy.Status.LastRotation != nil {
		nextRotation = policy.Status.LastRotation.Time.Add(interval)
	} else {
		// No previous rotation, schedule first rotation based on secret creation
		if sourceSecret.CreationTimestamp.IsZero() {
			nextRotation = time.Now().Add(interval)
		} else {
			nextRotation = sourceSecret.CreationTimestamp.Add(interval)
		}
	}

	// Update next rotation time in status
	nextRotationTime := metav1.NewTime(nextRotation)
	policy.Status.NextRotation = &nextRotationTime

	now := time.Now()
	if now.Before(nextRotation) {
		// Not time for rotation yet
		r.setCondition(policy, genesisv1alpha1.ConditionTypeRotationReady, metav1.ConditionTrue,
			genesisv1alpha1.ReasonRotationScheduled,
			fmt.Sprintf("Next rotation scheduled for %s", nextRotation.Format(time.RFC3339)))
		r.setCondition(policy, genesisv1alpha1.ConditionTypeRotationDue, metav1.ConditionFalse,
			genesisv1alpha1.ReasonRotationScheduled, "Rotation not yet due")

		policy.Status.ObservedGeneration = policy.Generation
		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}

		// Requeue at the next rotation time
		requeueAfter := nextRotation.Sub(now)
		logger.Info("Rotation not due yet", "nextRotation", nextRotation, "requeueAfter", requeueAfter)
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Rotation is due
	logger.Info("Rotation is due, starting rotation process")
	r.setCondition(policy, genesisv1alpha1.ConditionTypeRotationDue, metav1.ConditionTrue,
		genesisv1alpha1.ReasonRotationInProgress, "Rotation in progress")

	// Perform the rotation
	if err := r.performRotation(ctx, policy, sourceSecret); err != nil {
		logger.Error(err, "Failed to perform rotation")
		r.setCondition(policy, genesisv1alpha1.ConditionTypeRotationReady, metav1.ConditionFalse,
			genesisv1alpha1.ReasonRotationFailed, err.Error())

		// Record failed rotation event
		r.Recorder.Event(policy, corev1.EventTypeWarning, "RotationFailed", err.Error())

		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Update status after successful rotation
	policy.Status.LastRotation = &genesisv1alpha1.RotationStatus{
		Time:       metav1.Now(),
		NewVersion: sourceSecret.ResourceVersion,
		Success:    true,
		Message:    "Rotation completed successfully",
	}
	policy.Status.RotationCount++

	// Calculate next rotation time
	newNextRotation := metav1.NewTime(time.Now().Add(interval))
	policy.Status.NextRotation = &newNextRotation

	r.setCondition(policy, genesisv1alpha1.ConditionTypeRotationReady, metav1.ConditionTrue,
		genesisv1alpha1.ReasonRotationSucceeded, "Last rotation succeeded")
	r.setCondition(policy, genesisv1alpha1.ConditionTypeRotationDue, metav1.ConditionFalse,
		genesisv1alpha1.ReasonRotationScheduled, "Rotation completed, next scheduled")

	// Record successful rotation event
	r.Recorder.Event(policy, corev1.EventTypeNormal, "RotationSucceeded",
		fmt.Sprintf("Successfully rotated secret %s/%s", policy.Spec.Source.Namespace, policy.Spec.Source.Name))

	// Send notifications
	r.sendNotifications(ctx, policy)

	policy.Status.ObservedGeneration = policy.Generation
	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Rotation completed successfully",
		"rotationCount", policy.Status.RotationCount,
		"nextRotation", policy.Status.NextRotation)

	return ctrl.Result{RequeueAfter: interval}, nil
}

func (r *GenesisRotationPolicyReconciler) handleDeletion(ctx context.Context, policy *genesisv1alpha1.GenesisRotationPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(policy, rotationFinalizerName) {
		// Perform cleanup if needed
		logger.Info("Cleaning up rotation policy")

		// Remove finalizer
		controllerutil.RemoveFinalizer(policy, rotationFinalizerName)
		if err := r.Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *GenesisRotationPolicyReconciler) performRotation(ctx context.Context, policy *genesisv1alpha1.GenesisRotationPolicy, secret *corev1.Secret) error {
	logger := log.FromContext(ctx)

	strategyType := "BlueGreen"
	if policy.Spec.Strategy != nil && policy.Spec.Strategy.Type != "" {
		strategyType = policy.Spec.Strategy.Type
	}

	// 1. Find the managing GenesisBootstrap CR
	bootstrap, err := r.findGenesisBootstrap(ctx, policy.Spec.Source.Name, policy.Spec.Source.Namespace)
	if err != nil {
		return fmt.Errorf("cannot find GenesisBootstrap for rotation: %w", err)
	}

	// 2. Determine the secret key (from the GenesisBootstrap output spec)
	secretKey := bootstrap.Spec.Output.SecretKey

	// 3. Execute cryptographic rotation via bridge
	executor := r.GetRotationExecutor()
	artifacts, err := executor.Rotate(ctx, bootstrap, policy.Spec.Source.Name, policy.Spec.Source.Namespace, secretKey)
	if err != nil {
		return fmt.Errorf("rotation failed: %w", err)
	}

	// 4. Update GenesisBootstrap CR with new envelope
	bootstrap.Spec.Envelope.Ciphertext = base64.StdEncoding.EncodeToString(artifacts.EnvelopeCiphertext)
	bootstrap.Spec.Envelope.PublicKey = artifacts.PublicKey
	if err := r.Update(ctx, bootstrap); err != nil {
		return fmt.Errorf("failed to update GenesisBootstrap after rotation: %w", err)
	}

	// 5. Verify the rotated secret (best-effort — cache lag may delay visibility)
	secretName := policy.Spec.Source.Name
	secretNamespace := policy.Spec.Source.Namespace
	verifySecret := &corev1.Secret{}
	verifyKey := types.NamespacedName{Name: secretName, Namespace: secretNamespace}
	if err := r.Get(ctx, verifyKey, verifySecret); err != nil {
		logger.Info("Post-rotation verification: secret not yet visible (cache lag expected)", "error", err)
	} else {
		if _, ok := verifySecret.Data[secretKey]; !ok {
			logger.Info("Post-rotation verification: secret missing expected key", "key", secretKey)
			r.Recorder.Event(policy, corev1.EventTypeWarning, "RotationVerificationWarning",
				fmt.Sprintf("Post-rotation secret %s/%s missing expected key %q", secretNamespace, secretName, secretKey))
		}
		if verifySecret.Labels == nil || verifySecret.Labels["app.kubernetes.io/managed-by"] != "genesis-operator" {
			logger.Info("Post-rotation verification: secret missing genesis-operator managed-by label")
			r.Recorder.Event(policy, corev1.EventTypeWarning, "RotationVerificationWarning",
				fmt.Sprintf("Post-rotation secret %s/%s missing app.kubernetes.io/managed-by label", secretNamespace, secretName))
		}
	}

	// 6. Apply strategy-specific post-rotation annotations
	r.applyRotationAnnotations(ctx, secret, policy, strategyType)

	logger.Info("Cryptographic rotation completed", "strategy", strategyType)
	return nil
}

// findGenesisBootstrap finds the GenesisBootstrap CR that manages the given secret.
func (r *GenesisRotationPolicyReconciler) findGenesisBootstrap(ctx context.Context, secretName, secretNamespace string) (*genesisv1alpha1.GenesisBootstrap, error) {
	var bootstrapList genesisv1alpha1.GenesisBootstrapList
	if err := r.List(ctx, &bootstrapList); err != nil {
		return nil, fmt.Errorf("failed to list GenesisBootstrap resources: %w", err)
	}

	for i := range bootstrapList.Items {
		b := &bootstrapList.Items[i]
		if b.Spec.Output.SecretName == secretName && b.Spec.Output.SecretNamespace == secretNamespace {
			return b, nil
		}
	}

	return nil, fmt.Errorf("no GenesisBootstrap found for secret %s/%s", secretNamespace, secretName)
}

// applyRotationAnnotations updates secret annotations after a successful rotation.
func (r *GenesisRotationPolicyReconciler) applyRotationAnnotations(ctx context.Context, secret *corev1.Secret, policy *genesisv1alpha1.GenesisRotationPolicy, strategy string) {
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations["genesis.io/rotated-at"] = time.Now().Format(time.RFC3339)
	secret.Annotations["genesis.io/rotation-version"] = fmt.Sprintf("%d", policy.Status.RotationCount+1)
	secret.Annotations["genesis.io/rotation-strategy"] = strategy

	if err := r.Update(ctx, secret); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update secret annotations after rotation")
	}
}

func (r *GenesisRotationPolicyReconciler) sendNotifications(ctx context.Context, policy *genesisv1alpha1.GenesisRotationPolicy) {
	logger := log.FromContext(ctx)

	for _, notify := range policy.Spec.Notify {
		switch notify.Type {
		case "Event":
			// Events are already handled via the recorder
			logger.V(1).Info("Event notification already sent")

		case "Slack":
			if notify.WebhookSecretRef != nil {
				if err := r.sendSlackNotification(ctx, policy, notify); err != nil {
					logger.Error(err, "Failed to send Slack notification")
				}
			}

		case "Webhook":
			if notify.WebhookSecretRef != nil {
				if err := r.sendWebhookNotification(ctx, policy, notify); err != nil {
					logger.Error(err, "Failed to send webhook notification")
				}
			}

		case "PagerDuty":
			if notify.WebhookSecretRef != nil {
				if err := r.sendPagerDutyNotification(ctx, policy, notify); err != nil {
					logger.Error(err, "Failed to send PagerDuty notification")
				}
			}
		}
	}
}

func (r *GenesisRotationPolicyReconciler) sendSlackNotification(ctx context.Context, policy *genesisv1alpha1.GenesisRotationPolicy, notify genesisv1alpha1.NotificationSpec) error {
	logger := log.FromContext(ctx)

	if notify.WebhookSecretRef == nil {
		return fmt.Errorf("webhookSecretRef is required for Slack notifications")
	}

	// Fetch the webhook URL from the secret
	webhookURL, err := r.getWebhookURL(ctx, policy, notify.WebhookSecretRef)
	if err != nil {
		return fmt.Errorf("failed to get Slack webhook URL: %w", err)
	}

	// Build Slack-specific payload
	var message string
	if policy.Status.LastRotation != nil && policy.Status.LastRotation.Success {
		message = fmt.Sprintf("Genesis Rotation: %s in namespace %s rotated successfully",
			policy.Name, policy.Namespace)
	} else {
		message = fmt.Sprintf("Genesis Rotation: %s in namespace %s rotation failed",
			policy.Name, policy.Namespace)
	}

	slackPayload := map[string]string{
		"text": message,
	}

	// Send the webhook
	if err := r.postWebhook(ctx, webhookURL, slackPayload); err != nil {
		logger.Error(err, "Failed to send Slack notification")
		return err
	}

	logger.Info("Successfully sent Slack notification", "channel", notify.Channel)
	return nil
}

func (r *GenesisRotationPolicyReconciler) sendWebhookNotification(ctx context.Context, policy *genesisv1alpha1.GenesisRotationPolicy, notify genesisv1alpha1.NotificationSpec) error {
	logger := log.FromContext(ctx)

	if notify.WebhookSecretRef == nil {
		return fmt.Errorf("webhookSecretRef is required for webhook notifications")
	}

	// Fetch the webhook URL from the secret
	webhookURL, err := r.getWebhookURL(ctx, policy, notify.WebhookSecretRef)
	if err != nil {
		return fmt.Errorf("failed to get webhook URL: %w", err)
	}

	// Build webhook payload
	payload := r.buildWebhookPayload(policy)

	// Send the webhook
	if err := r.postWebhook(ctx, webhookURL, payload); err != nil {
		logger.Error(err, "Failed to send webhook notification")
		return err
	}

	logger.Info("Successfully sent webhook notification")
	return nil
}

// PagerDutyEvent represents the PagerDuty Events API v2 request format
type PagerDutyEvent struct {
	RoutingKey  string           `json:"routing_key"`
	EventAction string           `json:"event_action"`
	DedupKey    string           `json:"dedup_key,omitempty"`
	Payload     PagerDutyPayload `json:"payload"`
	Client      string           `json:"client,omitempty"`
	ClientURL   string           `json:"client_url,omitempty"`
	Links       []PagerDutyLink  `json:"links,omitempty"`
	Images      []PagerDutyImage `json:"images,omitempty"`
}

// PagerDutyPayload represents the payload section of a PagerDuty event
type PagerDutyPayload struct {
	Summary       string                 `json:"summary"`
	Severity      string                 `json:"severity"`
	Source        string                 `json:"source"`
	Component     string                 `json:"component,omitempty"`
	Group         string                 `json:"group,omitempty"`
	Class         string                 `json:"class,omitempty"`
	CustomDetails map[string]interface{} `json:"custom_details,omitempty"`
	Timestamp     string                 `json:"timestamp,omitempty"`
}

// PagerDutyLink represents a link in a PagerDuty event
type PagerDutyLink struct {
	Href string `json:"href"`
	Text string `json:"text,omitempty"`
}

// PagerDutyImage represents an image in a PagerDuty event
type PagerDutyImage struct {
	Src  string `json:"src"`
	Href string `json:"href,omitempty"`
	Alt  string `json:"alt,omitempty"`
}

// PagerDutyResponse represents the PagerDuty Events API v2 response
type PagerDutyResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	DedupKey string `json:"dedup_key,omitempty"`
}

// PagerDutyEventsAPIURL is the endpoint for PagerDuty Events API v2
const PagerDutyEventsAPIURL = "https://events.pagerduty.com/v2/enqueue"

func (r *GenesisRotationPolicyReconciler) sendPagerDutyNotification(ctx context.Context, policy *genesisv1alpha1.GenesisRotationPolicy, notify genesisv1alpha1.NotificationSpec) error {
	logger := log.FromContext(ctx)

	// Validate that we have a secret reference for the integration key
	if notify.WebhookSecretRef == nil {
		return fmt.Errorf("PagerDuty notification requires webhookSecretRef with integration key")
	}

	// Fetch the integration key from the secret
	integrationKey, err := r.getWebhookURL(ctx, policy, notify.WebhookSecretRef)
	if err != nil {
		return fmt.Errorf("failed to get PagerDuty integration key: %w", err)
	}

	// Build the PagerDuty event
	event := r.buildPagerDutyEvent(policy, integrationKey)

	// Send the event to PagerDuty
	if err := r.sendPagerDutyEvent(ctx, event); err != nil {
		return fmt.Errorf("failed to send PagerDuty event: %w", err)
	}

	logger.Info("Successfully sent PagerDuty notification",
		"policy", policy.Name,
		"dedup_key", event.DedupKey)
	return nil
}

// buildPagerDutyEvent constructs a PagerDuty Events API v2 event from the policy
func (r *GenesisRotationPolicyReconciler) buildPagerDutyEvent(policy *genesisv1alpha1.GenesisRotationPolicy, integrationKey string) PagerDutyEvent {
	// Determine severity based on rotation success
	severity := "info"
	eventAction := "trigger"
	summary := fmt.Sprintf("Genesis Rotation: %s/%s completed successfully", policy.Namespace, policy.Name)

	if policy.Status.LastRotation != nil && !policy.Status.LastRotation.Success {
		severity = "error"
		summary = fmt.Sprintf("Genesis Rotation: %s/%s failed", policy.Namespace, policy.Name)
		if policy.Status.LastRotation.Message != "" {
			summary = fmt.Sprintf("%s - %s", summary, policy.Status.LastRotation.Message)
		}
	}

	// Build custom details with rotation context
	customDetails := map[string]interface{}{
		"policy_name":    policy.Name,
		"namespace":      policy.Namespace,
		"rotation_count": policy.Status.RotationCount,
		"source_kind":    policy.Spec.Source.Kind,
		"source_name":    policy.Spec.Source.Name,
		"source_ns":      policy.Spec.Source.Namespace,
	}

	if policy.Status.LastRotation != nil {
		customDetails["rotation_time"] = policy.Status.LastRotation.Time.Format(time.RFC3339)
		customDetails["rotation_success"] = policy.Status.LastRotation.Success
		if policy.Status.LastRotation.OldVersion != "" {
			customDetails["old_version"] = policy.Status.LastRotation.OldVersion
		}
		if policy.Status.LastRotation.NewVersion != "" {
			customDetails["new_version"] = policy.Status.LastRotation.NewVersion
		}
		if policy.Status.LastRotation.Message != "" {
			customDetails["message"] = policy.Status.LastRotation.Message
		}
	}

	if policy.Spec.Strategy != nil {
		customDetails["strategy"] = policy.Spec.Strategy.Type
	}

	return PagerDutyEvent{
		RoutingKey:  integrationKey,
		EventAction: eventAction,
		DedupKey:    fmt.Sprintf("genesis-rotation/%s/%s", policy.Namespace, policy.Name),
		Payload: PagerDutyPayload{
			Summary:       summary,
			Severity:      severity,
			Source:        "genesis-operator",
			Component:     "rotation-policy",
			Group:         policy.Namespace,
			Class:         "secret-rotation",
			CustomDetails: customDetails,
			Timestamp:     time.Now().Format(time.RFC3339),
		},
		Client:    "Genesis Operator",
		ClientURL: "https://github.com/larsenclose/genesis",
	}
}

// sendPagerDutyEvent sends an event to the PagerDuty Events API v2
func (r *GenesisRotationPolicyReconciler) sendPagerDutyEvent(ctx context.Context, event PagerDutyEvent) error {
	// Marshal the event to JSON
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal PagerDuty event: %w", err)
	}

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "POST", PagerDutyEventsAPIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Send the request
	resp, err := client.Do(req) // #nosec G704 -- URL is the PagerDuty events API endpoint, a trusted service
	if err != nil {
		return fmt.Errorf("failed to send PagerDuty request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error details
	body, _ := io.ReadAll(resp.Body)

	// PagerDuty returns 202 Accepted on success
	if resp.StatusCode != http.StatusAccepted {
		var pdResp PagerDutyResponse
		if json.Unmarshal(body, &pdResp) == nil && pdResp.Message != "" {
			return fmt.Errorf("PagerDuty API error (status %d): %s", resp.StatusCode, pdResp.Message)
		}
		return fmt.Errorf("PagerDuty API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// WebhookPayload represents the structure of the webhook notification payload
type WebhookPayload struct {
	Event      string `json:"event"`
	PolicyName string `json:"policyName"`
	Namespace  string `json:"namespace"`
	Source     struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"source"`
	Rotation struct {
		Time       string `json:"time"`
		OldVersion string `json:"oldVersion,omitempty"`
		NewVersion string `json:"newVersion,omitempty"`
		Success    bool   `json:"success"`
		Message    string `json:"message,omitempty"`
	} `json:"rotation"`
	RotationCount int64     `json:"rotationCount"`
	Timestamp     time.Time `json:"timestamp"`
}

// getWebhookURL fetches the webhook URL from the referenced secret
func (r *GenesisRotationPolicyReconciler) getWebhookURL(ctx context.Context, policy *genesisv1alpha1.GenesisRotationPolicy, secretRef *genesisv1alpha1.SecretKeySelector) (string, error) {
	// Determine the namespace for the secret
	secretNamespace := secretRef.Namespace
	if secretNamespace == "" {
		secretNamespace = policy.Namespace
	}

	// Fetch the secret
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: secretNamespace,
	}

	if err := r.Get(ctx, secretKey, secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", secretNamespace, secretRef.Name, err)
	}

	// Extract the webhook URL from the secret
	webhookURLBytes, ok := secret.Data[secretRef.Key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s/%s", secretRef.Key, secretNamespace, secretRef.Name)
	}

	return string(webhookURLBytes), nil
}

// buildWebhookPayload constructs the webhook payload from the policy status
func (r *GenesisRotationPolicyReconciler) buildWebhookPayload(policy *genesisv1alpha1.GenesisRotationPolicy) WebhookPayload {
	payload := WebhookPayload{
		Event:         "rotation",
		PolicyName:    policy.Name,
		Namespace:     policy.Namespace,
		RotationCount: policy.Status.RotationCount,
		Timestamp:     time.Now(),
	}

	// Set source information
	payload.Source.Kind = policy.Spec.Source.Kind
	if payload.Source.Kind == "" {
		payload.Source.Kind = "Secret"
	}
	payload.Source.Name = policy.Spec.Source.Name
	payload.Source.Namespace = policy.Spec.Source.Namespace

	// Set rotation information if available
	if policy.Status.LastRotation != nil {
		payload.Rotation.Time = policy.Status.LastRotation.Time.Format(time.RFC3339)
		payload.Rotation.OldVersion = policy.Status.LastRotation.OldVersion
		payload.Rotation.NewVersion = policy.Status.LastRotation.NewVersion
		payload.Rotation.Success = policy.Status.LastRotation.Success
		payload.Rotation.Message = policy.Status.LastRotation.Message
	}

	return payload
}

// postWebhook sends the payload to the webhook URL
func (r *GenesisRotationPolicyReconciler) postWebhook(ctx context.Context, webhookURL string, payload interface{}) error {
	// Marshal the payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Send the request
	resp, err := client.Do(req) // #nosec G704 -- URL is from operator-configured webhook notification target
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook request failed with status code: %d", resp.StatusCode)
	}

	return nil
}

func (r *GenesisRotationPolicyReconciler) setCondition(policy *genesisv1alpha1.GenesisRotationPolicy, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()

	// Find existing condition
	for i, c := range policy.Status.Conditions {
		if c.Type == condType {
			if c.Status != status || c.Reason != reason || c.Message != message {
				policy.Status.Conditions[i] = metav1.Condition{
					Type:               condType,
					Status:             status,
					LastTransitionTime: now,
					Reason:             reason,
					Message:            message,
				}
			}
			return
		}
	}

	// Add new condition
	policy.Status.Conditions = append(policy.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	})
}

// SetupWithManager sets up the controller with the Manager
func (r *GenesisRotationPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&genesisv1alpha1.GenesisRotationPolicy{}).
		Complete(r)
}
