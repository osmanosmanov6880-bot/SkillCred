# Example least-privilege policy; adjust paths to the operator's Vault namespace.
path "secret/data/skillcred/production" {
  capabilities = ["read"]
}
path "secret/metadata/skillcred/production" {
  capabilities = ["read"]
}
# The application identity should not have write/delete access to its own secrets.
