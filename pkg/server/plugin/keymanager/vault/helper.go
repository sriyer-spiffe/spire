package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (p *Plugin) getPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	resp := new(keymanagerv1.GetPublicKeysResponse)
	for _, entry := range (p.entries) {
		resp.PublicKeys = append(resp.PublicKeys, clonePublicKey(entry))
	}

	return resp, nil
}

func (p *Plugin) getPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	p.mtx.RLock()
	defer p.mtx.RUnlock()

	resp := new(keymanagerv1.GetPublicKeyResponse)
	entry := p.entries[req.KeyId]
	if entry != nil {
		resp.PublicKey = clonePublicKey(entry)
	}

	return resp, nil
}

func (p *Plugin) generateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	newEntry, err := p.generateKeyEntry(req.KeyId, req.KeyType)
	if err != nil {
		return nil, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()


	err = p.vc.StashKeyEntry(req.KeyId, *newEntry, p.serverIdentifier)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "error stashing key on secure store %v", err)
	}
	
	p.entries[req.KeyId] = clonePublicKey(newEntry.PublicKey)
	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: clonePublicKey(newEntry.PublicKey),
	}, nil
}


func (p *Plugin) generateKeyEntry(keyID string, keyType keymanagerv1.KeyType) (e *keymanagerbase.KeyEntry, err error) {
	fmt.Println("generator !!! ", p.generator)
	var privateKey crypto.Signer
	switch keyType {
	case keymanagerv1.KeyType_EC_P256:
		privateKey, err = p.generator.GenerateEC256Key()
	case keymanagerv1.KeyType_EC_P384:
		privateKey, err = p.generator.GenerateEC384Key()
	case keymanagerv1.KeyType_RSA_2048:
		privateKey, err = p.generator.GenerateRSA2048Key()
	case keymanagerv1.KeyType_RSA_4096:
		privateKey, err = p.generator.GenerateRSA4096Key()
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unable to generate key %q for unknown key type %q", keyID, keyType)
	}
	if err != nil {
		return nil, err
	}

	entry, err := makeKeyEntry(keyID, keyType, privateKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to make key entry for new key %q: %v", keyID, err)
	}

	return entry, nil
}

func makeKeyEntry(keyID string, keyType keymanagerv1.KeyType, privateKey crypto.Signer) (*keymanagerbase.KeyEntry, error) {
	pkixData, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for entry %q: %w", keyID, err)
	}

	return &keymanagerbase.KeyEntry{
		PrivateKey: privateKey,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          keyID,
			Type:        keyType,
			PkixData:    pkixData,
			Fingerprint: makeFingerprint(pkixData),
		},
	}, nil
}

func clonePublicKey(publicKey *keymanagerv1.PublicKey) *keymanagerv1.PublicKey {
	return proto.Clone(publicKey).(*keymanagerv1.PublicKey)
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

func (p *Plugin) signData(req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	var signerOpts crypto.SignerOpts
	switch opts := req.SignerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		if opts.HashAlgorithm == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm is required")
		}
		signerOpts = crypto.Hash(opts.HashAlgorithm)
	case *keymanagerv1.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return nil, status.Error(codes.InvalidArgument, "PSS options are nil")
		}
		if opts.PssOptions.HashAlgorithm == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm in PSS options is required")
		}
		signerOpts = &rsa.PSSOptions{
			SaltLength: int(opts.PssOptions.SaltLength),
			Hash:       crypto.Hash(opts.PssOptions.HashAlgorithm),
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported signer opts type %T", opts)
	}

	privateKey, fingerprint, err := p.getPrivateKeyAndFingerprint(req.KeyId)
	if err != nil  {
		if status.Code(err) == codes.NotFound {
			return nil, status.Errorf(codes.NotFound, "no such key %q", req.KeyId)
		}
		return nil, status.Errorf(codes.Internal, "signing failed with error - %v", err)
	}

	signature, err := privateKey.Sign(rand.Reader, req.Data, signerOpts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "keypair %q signing operation failed: %v", req.KeyId, err)
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signature,
		KeyFingerprint: fingerprint,
	}, nil
}

func (p *Plugin) getPrivateKeyAndFingerprint(id string) (crypto.Signer, string, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	entry, err := p.vc.FetchKeyEntry(id, p.serverIdentifier)
	if err != nil {
		return nil, "", err
	}

	return entry.PrivateKey, entry.PublicKey.Fingerprint, nil
}


type defaultGenerator struct{}

func (defaultGenerator) GenerateRSA2048Key() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func (defaultGenerator) GenerateRSA4096Key() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func (defaultGenerator) GenerateEC256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (defaultGenerator) GenerateEC384Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}