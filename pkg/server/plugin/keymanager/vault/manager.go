package vault

import (
	"context"
	"fmt"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
)

// GenerateKey implements the KeyManager GenerateKey RPC. Generates a new private key with the given ID.
// If a key already exists under that ID, it is overwritten and given a different fingerprint.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	
	fmt.Println("GenerateKey - key id on request ", req.KeyId, req.KeyType)


	return p.generateKey(ctx, req)
	// return nil, status.Error(codes.Unimplemented, "not implemented")
}

// GetPublicKey implements the KeyManager GetPublicKey RPC. Gets the public key information for the private key managed
// by the plugin with the given ID. If a key with the given ID does not exist, NOT_FOUND is returned.
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	
	p.logger.Info("GetPublicKey - key id on request ", req.KeyId)
	
	return p.getPublicKey(ctx, req)
}

// GetPublicKeys implements the KeyManager GetPublicKeys RPC. Gets all public key information for the private keys
// managed by the plugin.
func (p *Plugin) GetPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	
	p.logger.Info("GetPublicKeys - key id on request ", req.String())

	return p.getPublicKeys(ctx, req)
}

// SignData implements the KeyManager SignData RPC. Signs data with the private key identified by the given ID. If a key
// with the given ID does not exist, NOT_FOUND is returned. The response contains the signed data and the fingerprint of
// the key used to sign the data. See the PublicKey message for more details on the role of the fingerprint.
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	
	p.logger.Info("SingData ", req.String())

	return p.signData(req)

	// return nil, status.Error(codes.Unimplemented, "not implemented")
}

