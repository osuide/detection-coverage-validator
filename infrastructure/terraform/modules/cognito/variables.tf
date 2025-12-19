variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "callback_urls" {
  description = "Allowed callback URLs for OAuth"
  type        = list(string)
  default     = ["http://localhost:3001/auth/callback"]
}

variable "logout_urls" {
  description = "Allowed logout URLs"
  type        = list(string)
  default     = ["http://localhost:3001"]
}

variable "enable_google_idp" {
  description = "Enable Google as identity provider"
  type        = bool
  default     = false
}

variable "google_client_id" {
  description = "Google OAuth client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "google_client_secret" {
  description = "Google OAuth client secret"
  type        = string
  default     = ""
  sensitive   = true
}

# GitHub Identity Provider
variable "enable_github_idp" {
  description = "Enable GitHub as identity provider"
  type        = bool
  default     = false
}

variable "github_client_id" {
  description = "GitHub OAuth App client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "github_client_secret" {
  description = "GitHub OAuth App client secret"
  type        = string
  default     = ""
  sensitive   = true
}

# Microsoft/Azure AD Identity Provider
variable "enable_microsoft_idp" {
  description = "Enable Microsoft/Azure AD as identity provider"
  type        = bool
  default     = false
}

variable "microsoft_client_id" {
  description = "Microsoft/Azure AD OAuth client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "microsoft_client_secret" {
  description = "Microsoft/Azure AD OAuth client secret"
  type        = string
  default     = ""
  sensitive   = true
}

variable "microsoft_tenant_id" {
  description = "Microsoft/Azure AD tenant ID (use 'common' for multi-tenant)"
  type        = string
  default     = "common"
}
