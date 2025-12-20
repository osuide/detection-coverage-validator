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

# Note: GitHub authentication is handled by the backend directly (not via Cognito)
# Microsoft SSO has been removed from the product
