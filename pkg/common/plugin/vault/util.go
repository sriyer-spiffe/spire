package vault

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func ParseAuthMethod(config *Configuration) (AuthMethod, error) {
	var authMethod AuthMethod
	if config.TokenAuth != nil {
		authMethod = TOKEN
	}
	if config.CertAuth != nil {
		if err := checkForAuthMethodConfigured(authMethod); err != nil {
			return 0, err
		}
		authMethod = CERT
	}
	if config.AppRoleAuth != nil {
		if err := checkForAuthMethodConfigured(authMethod); err != nil {
			return 0, err
		}
		authMethod = APPROLE
	}
	if config.K8sAuth != nil {
		if err := checkForAuthMethodConfigured(authMethod); err != nil {
			return 0, err
		}
		authMethod = K8S
	}

	if authMethod != 0 {
		return authMethod, nil
	}

	return 0, status.Error(codes.InvalidArgument, "must be configured one of these authentication method 'Token, Client Certificate, AppRole or Kubernetes")
}


func checkForAuthMethodConfigured(authMethod AuthMethod) error {
	if authMethod != 0 {
		return status.Error(codes.InvalidArgument, "only one authentication method can be configured")
	}
	return nil
}