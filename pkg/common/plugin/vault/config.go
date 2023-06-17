package vault


// Type definitions taken from upstream vault plugin.
// TODO: check if we can make this common for both the upstream vault plugin and the
// 		 the keymanager plugin for vault.


type Configuration struct {
	// A URL of Vault server. (e.g., https://vault.example.com:8443/)
	VaultAddr string `hcl:"vault_addr" json:"vault_addr"`
	// Name of the mount point where PKI secret engine is mounted. (e.g., /<mount_point>/ca/pem)
	PKIMountPoint string `hcl:"pki_mount_point" json:"pki_mount_point"`
	// Configuration for the Token authentication method
	TokenAuth *TokenAuthConfig `hcl:"token_auth" json:"token_auth,omitempty"`
	// Configuration for the Client Certificate authentication method
	CertAuth *CertAuthConfig `hcl:"cert_auth" json:"cert_auth,omitempty"`
	// Configuration for the AppRole authentication method
	AppRoleAuth *AppRoleAuthConfig `hcl:"approle_auth" json:"approle_auth,omitempty"`
	// Configuration for the Kubernetes authentication method
	K8sAuth *K8sAuthConfig `hcl:"k8s_auth" json:"k8s_auth,omitempty"`
	// Path to a CA certificate file that the client verifies the server certificate.
	// Only PEM format is supported.
	CACertPath string `hcl:"ca_cert_path" json:"ca_cert_path"`
	// If true, vault client accepts any server certificates.
	// It should be used only test environment so on.
	InsecureSkipVerify bool `hcl:"insecure_skip_verify" json:"insecure_skip_verify"`
	// Name of the Vault namespace
	Namespace string `hcl:"namespace" json:"namespace"`
}


// TokenAuthConfig represents parameters for token auth method
type TokenAuthConfig struct {
	// Token string to set into "X-Vault-Token" header
	Token string `hcl:"token" json:"token"`
}

// CertAuthConfig represents parameters for cert auth method
type CertAuthConfig struct {
	// Name of the mount point where Client Certificate Auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/cert)
	CertAuthMountPoint string `hcl:"cert_auth_mount_point" json:"cert_auth_mount_point"`
	// Name of the Vault role.
	// If given, the plugin authenticates against only the named role.
	CertAuthRoleName string `hcl:"cert_auth_role_name" json:"cert_auth_role_name"`
	// Path to a client certificate file.
	// Only PEM format is supported.
	ClientCertPath string `hcl:"client_cert_path" json:"client_cert_path"`
	// Path to a client private key file.
	// Only PEM format is supported.
	ClientKeyPath string `hcl:"client_key_path" json:"client_key_path"`
}

// AppRoleAuthConfig represents parameters for AppRole auth method.
type AppRoleAuthConfig struct {
	// Name of the mount point where AppRole auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/approle)
	AppRoleMountPoint string `hcl:"approle_auth_mount_point" json:"approle_auth_mount_point"`
	// An identifier that selects the AppRole
	RoleID string `hcl:"approle_id" json:"approle_id"`
	// A credential that is required for login.
	SecretID string `hcl:"approle_secret_id" json:"approle_secret_id"`
}

// K8sAuthConfig represents parameters for Kubernetes auth method.
type K8sAuthConfig struct {
	// Name of the mount point where Kubernetes auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/kubernetes)
	K8sAuthMountPoint string `hcl:"k8s_auth_mount_point" json:"k8s_auth_mount_point"`
	// Name of the Vault role.
	// The plugin authenticates against the named role.
	K8sAuthRoleName string `hcl:"k8s_auth_role_name" json:"k8s_auth_role_name"`
	// Path to the Kubernetes Service Account Token to use authentication with the Vault.
	TokenPath string `hcl:"token_path" json:"token_path"`
}