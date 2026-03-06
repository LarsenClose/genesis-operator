package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	genesisv1alpha1 "github.com/larsenclose/genesis/pkg/api/v1alpha1"
)

func TestGetBootstrapInjector(t *testing.T) {
	r := &GenesisBootstrapReconciler{}

	// Default: returns BridgeBootstrapInjector
	bootstrap := &genesisv1alpha1.GenesisBootstrap{}
	injector := r.getBootstrapInjector(bootstrap)
	_, isBridge := injector.(*BridgeBootstrapInjector)
	assert.True(t, isBridge, "default should be BridgeBootstrapInjector")

	// With AdditionalNamespaces: still returns BridgeBootstrapInjector
	bootstrap.Spec.Output.AdditionalNamespaces = []string{"ns-a", "ns-b"}
	injector = r.getBootstrapInjector(bootstrap)
	_, isBridge = injector.(*BridgeBootstrapInjector)
	assert.True(t, isBridge, "should use bridge even with AdditionalNamespaces")

	// With explicit override: returns the override
	mock := &LegacyBootstrapInjector{}
	r.BootstrapInjector = mock
	injector = r.getBootstrapInjector(bootstrap)
	assert.Equal(t, mock, injector, "explicit override should be respected")
}
