package vault

import (
	context "context"
	
	"os"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/vault"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)


func BuiltIn() catalog.BuiltIn {
	return builtIn(New())
}


func builtIn(p *Plugin) catalog.BuiltIn {
	p.logger.Info("loading vault key manager plugin")
	return catalog.MakeBuiltIn(vault.PluginName,
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	generator keymanagerbase.Generator
	mtx    *sync.RWMutex
	logger hclog.Logger

	authMethod vault.AuthMethod
	cc         *vault.ClientConfig
	vc         *vault.Client
	serverIdentifier string

	entries map[string]*keymanagerv1.PublicKey

	hooks struct {
		lookupEnv func(string) (string, bool)
	}
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(vault.Configuration)

	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	am, err := vault.ParseAuthMethod(config)
	if err != nil {
		return nil, err
	}
	cp, err := p.genClientParams(am, config)
	if err != nil {
		return nil, err
	}
	vcConfig, err := vault.NewClientConfig(cp, p.logger)
	if err != nil {
		return nil, err
	}

	p.authMethod = am
	p.cc = vcConfig



	_, err = p.getVaultClient()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "vault client creation failed %v", err)
	}	

	return &configv1.ConfigureResponse{}, nil
}

func New() *Plugin {
	p := &Plugin{
		mtx: &sync.RWMutex{},
		generator: &defaultGenerator{},
		entries: make(map[string]*keymanagerv1.PublicKey),
		logger: hclog.New(&hclog.LoggerOptions{}),
	}
	p.hooks.lookupEnv = os.LookupEnv
	return p
}

func (p *Plugin) genClientParams(method vault.AuthMethod, config *vault.Configuration) (*vault.ClientParams, error) {
	cp := &vault.ClientParams{
		VaultAddr:     p.getEnvOrDefault(vault.EnvVaultAddr, config.VaultAddr),
		CACertPath:    p.getEnvOrDefault(vault.EnvVaultCACert, config.CACertPath),
		PKIMountPoint: config.PKIMountPoint,
		TLSSKipVerify: config.InsecureSkipVerify,
		Namespace:     p.getEnvOrDefault(vault.EnvVaultNamespace, config.Namespace),
	}

	switch method {
	case vault.TOKEN:
		cp.Token = p.getEnvOrDefault(vault.EnvVaultToken, config.TokenAuth.Token)
	case vault.CERT:
		cp.CertAuthMountPoint = config.CertAuth.CertAuthMountPoint
		cp.CertAuthRoleName = config.CertAuth.CertAuthRoleName
		cp.ClientCertPath = p.getEnvOrDefault(vault.EnvVaultClientCert, config.CertAuth.ClientCertPath)
		cp.ClientKeyPath = p.getEnvOrDefault(vault.EnvVaultClientKey, config.CertAuth.ClientKeyPath)
	case vault.APPROLE:
		cp.AppRoleAuthMountPoint = config.AppRoleAuth.AppRoleMountPoint
		cp.AppRoleID = p.getEnvOrDefault(vault.EnvVaultAppRoleID, config.AppRoleAuth.RoleID)
		cp.AppRoleSecretID = p.getEnvOrDefault(vault.EnvVaultAppRoleSecretID, config.AppRoleAuth.SecretID)
	case vault.K8S:
		if config.K8sAuth.K8sAuthRoleName == "" {
			return nil, status.Error(codes.InvalidArgument, "k8s_auth_role_name is required")
		}
		if config.K8sAuth.TokenPath == "" {
			return nil, status.Error(codes.InvalidArgument, "token_path is required")
		}
		cp.K8sAuthMountPoint = config.K8sAuth.K8sAuthMountPoint
		cp.K8sAuthRoleName = config.K8sAuth.K8sAuthRoleName
		cp.K8sAuthTokenPath = config.K8sAuth.TokenPath
	}

	return cp, nil
}

func (p *Plugin) getEnvOrDefault(envKey, fallback string) string {
	if value, ok := p.hooks.lookupEnv(envKey); ok {
		return value
	}
	return fallback
}

