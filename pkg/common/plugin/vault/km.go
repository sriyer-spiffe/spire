package vault

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (c *Client) StashKeyEntry(keyID string, entry *keymanagerbase.KeyEntry, spireServerID string) (err error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(entry.PrivateKey)
	if err != nil {
		return status.Errorf(codes.Internal, "error transforming key %v", err)
	}

	_, err = c.vaultClient.Logical().Write(fmt.Sprintf("testing/spire/pki/%s/%s", spireServerID, keyID), map[string]interface{}{"key": keyBytes})
	if err != nil {
		return status.Errorf(codes.Internal, "error writing to vault %v ", err)
	}

	return
}

func (c *Client) FetchKeyEntry(keyId, spireServerID string) (entry keymanagerbase.KeyEntry, err error) {
	secret, err := c.vaultClient.Logical().Read(fmt.Sprintf("testing/spire/pki/%s/%s", spireServerID, keyId))
	if err != nil {
		err = status.Errorf(codes.Internal, "error reading from vault %v", err)
		return
	}
	
	vaultData, ok := secret.Data["key"].(string)
	if !ok {
		err = status.Errorf(codes.Internal, "no data found on vault for key %s", keyId)
		return
	}
	data, err := base64.RawStdEncoding.DecodeString(vaultData)
	if err != nil {
		err = status.Errorf(codes.Internal, "error decoding data from vault %v", err)
		return
	}
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		err = status.Errorf(codes.Internal, "unable to parse key %q: %v", keyId, err)
		return
	}
	e, err := keymanagerbase.MakeKeyEntryFromKey(keyId, key)
	if err != nil {
		err = status.Errorf(codes.Internal, "unable to make entry %q: %v", keyId, err)
		return
	}
	entry = *e
	return
}
