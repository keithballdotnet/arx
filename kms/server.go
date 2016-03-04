// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

/*import (
	"brainloop/configuration"
	"brainloop/shared/rest"
	"brainloop/util"
	"brainloop/util/authhelpers"
	"brainloop/util/blctx"
	"brainloop/util/deployment"
	"brainloop/util/logging/diagnostics"
	"brainloop/util/security/crypto"
	"strings"

	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/rcrowley/go-tigertonic"
)

var (
	// SharedKey This key is used for authentication with the server
	SharedKey = ""
)

// AuthContext information for Marshaled calls
type AuthContext struct {
	UserAgent  string
	RemoteAddr string
}

// GetAuthContext is used to return UserAgent and Request info from the request
func GetAuthContext(r *http.Request) (http.Header, error) {

	tigertonic.Context(r).(*AuthContext).UserAgent = r.UserAgent()
	tigertonic.Context(r).(*AuthContext).RemoteAddr = RequestAddr(r)

	// Authoritze the request
	if !authhelpers.AuthorizeRequestWithKey(blctx.NewFromRequest(r), SharedKey, r.Method, r.URL, r.Header) {
		return nil, tigertonic.Unauthorized{Err: rest.AccessDeniedError}
	}

	return nil, nil
}

// StartListener start a HTTP listener
func StartListener(cert string, certKey string, buildVersion string, buildDate string) {
	// Set up the auth key
	SetupAuthenticationKey()

	// Set-up API listeners
	mux := tigertonic.NewTrieServeMux()
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSListKeys, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(listKeysHandler), "ListKeysHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSCreateKey, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(createKeyHandler), "CreateKeyHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSGenerateDataKey, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(generateDataKeyHandler), "GenerateDataKeyHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSEnableKey, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(enableKeyHandler), "EnableKeyHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSDisableKey, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(disableKeyHandler), "DisableKeyHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSRotateKey, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(rotateKeyHandler), "RotateKeyHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSDecrypt, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(decryptHandler), "DecryptHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSEncrypt, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(encryptHandler), "EncryptHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSReencrypt, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(reEncryptHandler), "ReEncryptHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSSign, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(signHandler), "SignHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSVerify, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(verifyHandler), "VerifyHandler", nil)))
	mux.Handle("GET", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSGetSecret, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(getSecretHandler), "GetSecretHandler", nil)))
	mux.Handle("POST", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSSetSecret, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(setSecretHandler), "SetSecretHandler", nil)))
	mux.Handle("GET", rest.APIURLGoKMSPrefix+rest.APIURLGoKMSGetSecrets, tigertonic.If(GetAuthContext, tigertonic.Timed(tigertonic.Marshaled(listSecretsHandler), "ListSecretsHandler", nil)))
	// TODO: Delete secrets

	deployment.RegisterHTTPHandlers(mux, rest.APIURLGoKMSPrefix, rest.ServiceVersionInfo{BuildVersion: buildVersion, BuildDate: buildDate})

	aMux := tigertonic.ApacheLogged(tigertonic.WithContext(mux, AuthContext{}))
	aMux.Logger = log.New(diagnostics.GetStandardLogOutput(), diagnostics.GetStandardLogPrefix(), diagnostics.GetStandardLogFlags())

	server := tigertonic.NewServer(fmt.Sprintf(":%d", deployment.GoKMSPort), aMux)

	diagnostics.Debugf(nil, "GO-KMS listening on: %s", fmt.Sprintf(":%d", deployment.GoKMSPort))
	//diagnostics.Log(diagnostics.PriDebug, nil, "GO-KMS listening on: %s", fmt.Sprintf(":%d", deployment.GoKMSPort))

	if err := util.FilesMustExist(cert, certKey); err != nil {
		log.Fatal(err)
	}

	// server.Close to stop gracefully.
	go func() {
		diagnostics.Debugln(nil, "SSL Enabled")
		if err := server.ListenAndServeTLS(cert, certKey); err != nil {
			diagnostics.Criticalf(nil, "Go-KMS Service Fatal: %v", err)
		}
	}()
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	diagnostics.Debugln(nil, <-ch)
	if err := server.Close(); err != nil {
		diagnostics.Errorf(nil, "Error shutting down server: %v", err)
	}

	/*aMux := tigertonic.ApacheLogged(tigertonic.WithContext(mux, AuthContext{}))
	aMux.Logger = log.New(diagnostics.GetStandardLogOutput(), diagnostics.GetStandardLogPrefix(), diagnostics.GetStandardLogFlags())

	// Log to Console
	server := tigertonic.NewServer(fmt.Sprintf("%s:%s", Config["GOKMS_HOST"], Config["GOKMS_PORT"]), aMux)
	if err := server.ListenAndServeTLS(Config["GOKMS_SSL_CERT"], Config["GOKMS_SSL_KEY"]); err != nil {
		Exit(fmt.Sprintf("Problem starting server: %v ", err), 2)
	}* /

}

// SetupAuthenticationKey  - This deals with setting an auth key for the service
func SetupAuthenticationKey() {
	config := configuration.LoadGoKMSConfiguration()
	SharedKey = config.AuthKey
}

// getSecretHandler will get a secret
func getSecretHandler(u *url.URL, h http.Header, _ interface{}, c *AuthContext) (int, http.Header, *rest.GetSecretResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "getSecretHandler")

	diagnostics.Debugln(ctx, "getSecretHandler: Starting...")

	secretID := u.Query().Get("SecretID")

	// Need an ID to work on
	if secretID == "" {
		return http.StatusBadRequest, nil, nil, nil
	}

	// Get a secret
	secret, err := KmsCrypto.GetSecret(ctx, secretID)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		if util.IsNotFoundError(err) {
			return http.StatusNotFound, nil, nil, nil
		}

		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.GetSecretResponse{Value: secret.Secret, SecretID: secretID}, nil
}

// listSecretsHandler will list secrets
func listSecretsHandler(u *url.URL, h http.Header, _ interface{}, c *AuthContext) (int, http.Header, *rest.GetSecretsResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "listSecretsHandler")

	diagnostics.Debugln(ctx, "listSecretsHandler: Starting...")

	// Get a secret
	secrets, err := KmsCrypto.ListSecrets(ctx)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.GetSecretsResponse{SecretIDs: secrets}, nil
}

// setSecretHandler will set a secret
func setSecretHandler(u *url.URL, h http.Header, setSecretRequest *rest.SetSecretRequest, c *AuthContext) (int, http.Header, *rest.SetSecretResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "setSecretHandler")

	diagnostics.Debugln(ctx, "setSecretHandler: Starting...")

	secretID := u.Query().Get("SecretID")

	// Need an ID to work on
	if secretID == "" {
		return http.StatusBadRequest, nil, nil, nil
	}

	// Reencrypt the data
	err = KmsCrypto.SetSecret(ctx, secretID, setSecretRequest.Value, setSecretRequest.Overwrite)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			return http.StatusConflict, nil, nil, nil
		}

		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.SetSecretResponse{Value: setSecretRequest.Value, SecretID: secretID}, nil
}

// verifyHandler will verfify a signature
func verifyHandler(u *url.URL, h http.Header, verifyRequest *rest.VerifyRequest, c *AuthContext) (int, http.Header, *rest.VerifyResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "verifyHandler")

	diagnostics.Debugln(ctx, "verifyHandler: Starting...")

	// Reencrypt the data
	ok, err := KmsCrypto.Verify(verifyRequest.Hashdata, verifyRequest.Signature)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.VerifyResponse{Verified: ok}, nil
}

// signHandler will sign a passed hash with a ECDSA key
func signHandler(u *url.URL, h http.Header, signRequest *rest.SignRequest, c *AuthContext) (int, http.Header, *rest.SignResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "signHandler")

	diagnostics.Debugln(ctx, "SignHandler: Starting...")
	//diagnostics.Debugf(ctx, "SignHandler: Starting... \n %v", stringhelper.PrintJSON("SignRequest", signRequest))

	// Reencrypt the data
	sig, err := KmsCrypto.Sign(ctx, signRequest.Hashdata, signRequest.KeyID)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.SignResponse{Signature: sig}, nil
}

// reEncryptHandler will re-encrypt the passed Ciphertext with a new Key
func reEncryptHandler(u *url.URL, h http.Header, reEncryptRequest *rest.ReEncryptRequest, c *AuthContext) (int, http.Header, *rest.ReEncryptResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "reEncryptHandler")

	diagnostics.Debugln(ctx, "ReEncryptHandler: Starting...")

	// Reencrypt the data
	ciphertextBlob, sourceKeyID, err := KmsCrypto.ReEncrypt(ctx, reEncryptRequest.CiphertextBlob, reEncryptRequest.DestinationKeyID)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.ReEncryptResponse{CiphertextBlob: ciphertextBlob, KeyID: reEncryptRequest.DestinationKeyID, SourceKeyID: sourceKeyID}, nil
}

// createKeyHandler will generate a new stored key
func createKeyHandler(u *url.URL, h http.Header, createKeyRequest *rest.CreateKeyRequest, c *AuthContext) (int, http.Header, *rest.CreateKeyResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "createKeyHandler")

	diagnostics.Debugln(ctx, "CreateKeyHandler: Starting...")

	// Encrypt the key with the master key
	metadata, err := KmsCrypto.CreateKey(ctx, createKeyRequest.Description, createKeyRequest.KeyType)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		if err.Error() == "Already exists" {
			return http.StatusConflict, nil, nil, nil
		}

		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.CreateKeyResponse{KeyMetadata: metadata}, nil
}

// listKeysHandler will list all the stored
func listKeysHandler(u *url.URL, h http.Header, listKeysRequest *rest.ListKeysRequest, c *AuthContext) (int, http.Header, *rest.ListKeysResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "ListKeysRequest")

	diagnostics.Debugln(ctx, "ListKeysRequest: Starting...")

	// Encrypt the key with the master key
	metadata, err := KmsCrypto.ListKeys(ctx)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.ListKeysResponse{KeyMetadata: metadata}, nil
}

// rotateKeyHandler will rotate an AES key
func rotateKeyHandler(u *url.URL, h http.Header, rotateKeyRequest *rest.RotateKeyRequest, c *AuthContext) (int, http.Header, *rest.RotateKeyResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "rotateKeyHandler")

	diagnostics.Debugln(ctx, "rotateKeyHandler: Starting...")

	// Enable the key
	err = KmsCrypto.RotateKey(ctx, rotateKeyRequest.KeyID)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.RotateKeyResponse{Success: true}, nil
}

// enableKeyHandler will enable a AES key for use
func enableKeyHandler(u *url.URL, h http.Header, enableKeyRequest *rest.EnableKeyRequest, c *AuthContext) (int, http.Header, *rest.EnableKeyResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "enableKeyHandler")

	diagnostics.Debugln(ctx, "EnableKeyRequest: Starting...")

	// Enable the key
	metadata, err := KmsCrypto.EnableKey(ctx, enableKeyRequest.KeyID)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.EnableKeyResponse{KeyMetadata: metadata}, nil
}

// disableKeyHandler will disable a AES key for use
func disableKeyHandler(u *url.URL, h http.Header, disableKeyRequest *rest.DisableKeyRequest, c *AuthContext) (int, http.Header, *rest.DisableKeyResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "disableKeyHandler")

	diagnostics.Debugln(ctx, "DisableKeyRequest: Starting...")

	// Disable the key
	metadata, err := KmsCrypto.DisableKey(ctx, disableKeyRequest.KeyID)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.DisableKeyResponse{KeyMetadata: metadata}, nil
}

// generateDataKeyHandler will generate a new AES key for use by a client
func generateDataKeyHandler(u *url.URL, h http.Header, dataKeyRequest *rest.GenerateDataKeyRequest, c *AuthContext) (int, http.Header, *rest.GenerateDataKeyResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "GenerateDataKeyRequest")

	diagnostics.Debugln(ctx, "GenerateDataKeyRequest: Starting...")

	// Create a new key
	aesKey := crypto.GenerateAesKey()

	// Encrypt the key with the master key
	encryptedData, err := KmsCrypto.Encrypt(ctx, aesKey, dataKeyRequest.KeyID)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.GenerateDataKeyResponse{Plaintext: aesKey, CiphertextBlob: encryptedData}, nil
}

// encryptHandler will encrypt the passed data with the specified key
func encryptHandler(u *url.URL, h http.Header, encryptRequest *rest.EncryptRequest, c *AuthContext) (int, http.Header, *rest.EncryptResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "EncryptHandler")

	diagnostics.Debugln(ctx, "EncryptHandler: Starting...")

	// Encrypt the data with the key specified and return the encrypted data
	encryptedData, err := KmsCrypto.Encrypt(ctx, encryptRequest.Plaintext, encryptRequest.KeyID)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.EncryptResponse{CiphertextBlob: encryptedData}, nil
}

// decryptHandler will decrypt the passed data with the specified key
func decryptHandler(u *url.URL, h http.Header, decryptRequest *rest.DecryptRequest, c *AuthContext) (int, http.Header, *rest.DecryptResponse, error) {
	ctx := blctx.FromJSONString(h.Get("x-brainloop-ctx"))
	var err error
	defer util.CatchPanic(ctx, &err, "decryptHandler")

	diagnostics.Debugln(ctx, "DecryptHandler: Starting...")

	// Decrypt
	decryptedData, _, err := KmsCrypto.Decrypt(ctx, decryptRequest.CiphertextBlob)
	if err != nil {
		diagnostics.Errorf(ctx, "Error: %v", err)
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &rest.DecryptResponse{Plaintext: decryptedData}, nil
}

// RequestAddr Get the request address
func RequestAddr(r *http.Request) string {
	// Get the IP of the request
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// TestSetSecretHandler exposed for fuzz testing
func TestSetSecretHandler(u *url.URL, h http.Header, setSecretRequest *rest.SetSecretRequest, c *AuthContext) (int, http.Header, *rest.SetSecretResponse, error) {
	return setSecretHandler(u, h, setSecretRequest, c)
}

// TestGetSecretHandler exposed for fuzz testing
func TestGetSecretHandler(u *url.URL, h http.Header, _ interface{}, c *AuthContext) (int, http.Header, *rest.GetSecretResponse, error) {
	return getSecretHandler(u, h, nil, c)
}
*/
