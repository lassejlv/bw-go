// Package biometrics ports the CLI's biometric unlock through the Bitwarden desktop app
// (apps/cli/src/key-management/cli-biometrics-service.ts). The official CLI only talks to the
// desktop app when the "biometrics-sdk-ipc" feature flag is on: it then sends SDK IPC RPC requests
// (bitwarden-shared-unlock's GetBiometricsStatus / UnlockBiometrics / AuthenticateBiometrics) to
// the desktop renderer through the desktop_proxy, Noise encrypted (internal/ipc). With the flag off
// (the default) biometrics is reported as unsupported and unlock falls back to the master
// password; there is no other desktop protocol in the CLI.
package biometrics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	bwauth "github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/features"
	"github.com/lassejlv/bw-go/internal/ipc"
)

// BiometricsSDKIPC is FeatureFlag.BiometricsSDKIPC (default false).
const BiometricsSDKIPC = "biometrics-sdk-ipc"

// Status is the TypeScript BiometricsStatus enum.
type Status int

// BiometricsStatus values.
const (
	Available Status = iota
	UnlockNeeded
	HardwareUnavailable
	AutoSetupNeeded
	ManualSetupNeeded
	PlatformUnsupported
	DesktopDisconnected
	NotEnabledLocally
	NotEnabledInConnectedDesktopApp
	NativeMessagingPermissionMissing
)

// Timeouts of CliBiometricsService.
const (
	NoInteractionTimeout = 5 * time.Second
	InteractionTimeout   = 60 * time.Second
)

// NewTransport creates the transport to the desktop app. Tests replace it.
var NewTransport = func(log ipc.Logger) ipc.Transport { return ipc.NewDesktopTransport(log) }

// Service is CliBiometricsService.
type Service struct {
	app  *app.App
	flag func() bool
	ipc  *ipc.DesktopService
	log  ipc.Logger
}

// NewService creates the biometrics service for a.
func NewService(a *app.App) *Service {
	log := Logger()
	s := &Service{
		app:  a,
		flag: func() bool { return features.Enabled(a, BiometricsSDKIPC) },
		log:  log,
	}
	s.ipc = ipc.NewDesktopService(func() ipc.Transport { return NewTransport(log) }, log)
	return s
}

// Logger mirrors the CLI's ConsoleLogService at info level: silent unless BITWARDENCLI_DEBUG is
// "true", then stdout (stderr when BW_RESPONSE is "true").
func Logger() ipc.Logger {
	return func(msg string) {
		if os.Getenv("BITWARDENCLI_DEBUG") != "true" {
			return
		}
		w := os.Stdout
		if os.Getenv("BW_RESPONSE") == "true" {
			w = os.Stderr
		}
		fmt.Fprintln(w, msg)
	}
}

func (s *Service) sdkIpcEnabled() bool { return s.flag() }

// ConnectToDesktop is ServiceContainer.connectToDesktop: with the flag on it verifies the desktop
// connection (DiscoverRequest and the minimum version) and only logs failures, since desktop IPC
// is optional.
func (s *Service) ConnectToDesktop() {
	if !s.sdkIpcEnabled() {
		return
	}
	v, err := s.ipc.VerifyDesktopConnection(context.Background())
	if err != nil {
		s.log("[IPC] Could not connect to Bitwarden Desktop " + err.Error())
		return
	}
	s.log("[IPC] Connected to Bitwarden Desktop " + v)
}

// Close disconnects from the desktop app (ServiceContainer.dispose).
func (s *Service) Close() { s.ipc.Disconnect() }

// AuthenticateWithBiometrics triggers a biometric user verification in the desktop app.
func (s *Service) AuthenticateWithBiometrics() bool {
	if !s.sdkIpcEnabled() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), InteractionTimeout)
	defer cancel()
	var ok bool
	// AuthenticateBiometricsRequest is a unit struct, serialized as null.
	if err := s.ipc.Client().Request(ctx, ipc.DesktopRenderer, "AuthenticateBiometrics", nil, &ok); err != nil {
		s.log("CLI biometric authentication failed " + err.Error())
		return false
	}
	return ok
}

// GetBiometricsStatus returns the status for the active account.
func (s *Service) GetBiometricsStatus() Status {
	acct := s.app.ActiveAccount()
	if acct == nil {
		return NotEnabledLocally
	}
	return s.GetBiometricsStatusForUser(acct.UserID)
}

type userRequest struct {
	UserID string `json:"user_id"`
}

// sdkStatus maps the SDK BiometricsStatus (serialized as its variant name) with
// toTsBiometricsStatus. Unknown variants fail to deserialize.
func sdkStatus(raw string) (Status, bool) {
	switch raw {
	case "Available":
		return Available, true
	case "HardwareUnavailable":
		return HardwareUnavailable, true
	case "UnlockNeeded":
		return UnlockNeeded, true
	case "NotEnabled":
		return NotEnabledLocally, true
	}
	return 0, false
}

// GetBiometricsStatusForUser asks the desktop app whether it can unlock userID with biometrics.
func (s *Service) GetBiometricsStatusForUser(userID string) Status {
	if !s.sdkIpcEnabled() {
		return PlatformUnsupported
	}
	ctx, cancel := context.WithTimeout(context.Background(), NoInteractionTimeout)
	defer cancel()
	var raw json.RawMessage
	if err := s.ipc.Client().Request(ctx, ipc.DesktopRenderer, "GetBiometricsStatus", userRequest{UserID: userID}, &raw); err != nil {
		s.log("Could not query Bitwarden Desktop biometric status " + err.Error())
		return DesktopDisconnected
	}
	var name string
	_ = json.Unmarshal(raw, &name)
	st, ok := sdkStatus(name)
	if !ok {
		s.log("Could not query Bitwarden Desktop biometric status Failed to read response: unknown variant " + string(raw))
		return DesktopDisconnected
	}
	if st == NotEnabledLocally {
		return NotEnabledInConnectedDesktopApp
	}
	return st
}

// UnlockWithBiometricsForUser asks the desktop app to unlock userID with biometrics and returns
// the user key it hands over, or nil when the prompt was cancelled or anything failed.
func (s *Service) UnlockWithBiometricsForUser(userID string) *crypto.SymmetricKey {
	if !s.sdkIpcEnabled() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), InteractionTimeout)
	defer cancel()
	var resp struct {
		UserKey *string `json:"user_key"`
	}
	if err := s.ipc.Client().Request(ctx, ipc.DesktopRenderer, "UnlockBiometrics", userRequest{UserID: userID}, &resp); err != nil {
		s.log("CLI biometric unlock failed " + err.Error())
		return nil
	}
	if resp.UserKey == nil {
		return nil
	}
	userKey, err := crypto.KeyFromB64(*resp.UserKey)
	if err != nil {
		s.log("CLI biometric unlock failed " + err.Error())
		return nil
	}
	if !s.ValidateUserKey(userKey, userID) {
		s.log("CLI biometric unlock failed: desktop returned an invalid user key")
		return nil
	}
	return userKey
}

// ValidateUserKey is KeyService.validateUserKey: the key must decrypt the user's private key
// (and, for v2 accounts, the rest of the account cryptographic state).
func (s *Service) ValidateUserKey(userKey *crypto.SymmetricKey, userID string) bool {
	if userKey == nil {
		return false
	}
	d, err := s.app.Data()
	if err != nil {
		return false
	}
	acct := d.Accounts[userID]
	if acct == nil {
		return false
	}
	keys := bwauth.ParseAccountKeys(bwauth.GetAccountKeys(nil, acct))
	encPrivateKey := keys.WrappedPrivateKey()
	if encPrivateKey == "" {
		encPrivateKey = acct.EncPrivateKey
	}
	if encPrivateKey == "" {
		return false
	}
	// The private key must decrypt (and derive a public key); v2 state is verified as well.
	acc, err := bwauth.UnlockAccountKeys(keys, acct.EncPrivateKey, userKey)
	return err == nil && acc != nil && acc.PrivateKey != nil
}

// The remaining BiometricsService members are no-ops on the CLI.

// GetShouldAutopromptNow is always false.
func (s *Service) GetShouldAutopromptNow() bool { return false }

// CanEnableBiometricUnlock reports whether biometrics is available for the active account.
func (s *Service) CanEnableBiometricUnlock() bool { return s.GetBiometricsStatus() == Available }

// HasPersistentKey is always false: the CLI stores no biometric keys.
func (s *Service) HasPersistentKey(string) bool { return false }

// EnrollPersistent does nothing on the CLI.
func (s *Service) EnrollPersistent(string, *crypto.SymmetricKey) error { return nil }

// SetBiometricProtectedUnlockKeyForUser does nothing on the CLI.
func (s *Service) SetBiometricProtectedUnlockKeyForUser(string, *crypto.SymmetricKey) error {
	return nil
}

// DeleteBiometricUnlockKeyForUser does nothing on the CLI.
func (s *Service) DeleteBiometricUnlockKeyForUser(string) error { return nil }
