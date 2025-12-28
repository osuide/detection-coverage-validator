/**
 * WebAuthn browser API utilities.
 *
 * Handles the browser-side WebAuthn operations:
 * - Creating credentials (registration)
 * - Getting credentials (authentication)
 * - Converting between base64url and ArrayBuffer
 */

/**
 * Check if WebAuthn is supported in the current browser.
 */
export function isWebAuthnSupported(): boolean {
  return (
    window.PublicKeyCredential !== undefined &&
    typeof window.PublicKeyCredential === 'function'
  )
}

/**
 * Check if platform authenticator (Touch ID, Windows Hello) is available.
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  } catch {
    return false
  }
}

/**
 * Convert base64url string to ArrayBuffer.
 */
export function base64urlToBuffer(base64url: string): ArrayBuffer {
  // Replace base64url chars with base64 chars
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')

  // Pad with = to make it valid base64
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=')

  // Decode to binary string
  const binary = atob(padded)

  // Convert to ArrayBuffer
  const buffer = new ArrayBuffer(binary.length)
  const bytes = new Uint8Array(buffer)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }

  return buffer
}

/**
 * Convert ArrayBuffer to base64url string.
 */
export function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }

  // Convert to base64
  const base64 = btoa(binary)

  // Convert to base64url
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/**
 * Prepare server options for navigator.credentials.create().
 * Converts base64url strings to ArrayBuffers.
 */
export function prepareRegistrationOptions(
  options: PublicKeyCredentialCreationOptionsJSON
): PublicKeyCredentialCreationOptions {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToBuffer(options.user.id),
    },
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      ...cred,
      id: base64urlToBuffer(cred.id),
    })),
  }
}

/**
 * Prepare server options for navigator.credentials.get().
 * Converts base64url strings to ArrayBuffers.
 */
export function prepareAuthenticationOptions(
  options: PublicKeyCredentialRequestOptionsJSON
): PublicKeyCredentialRequestOptions {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: options.allowCredentials?.map((cred) => ({
      ...cred,
      id: base64urlToBuffer(cred.id),
    })),
  }
}

/**
 * Convert registration response to JSON for server verification.
 */
export function registrationResponseToJSON(
  credential: PublicKeyCredential
): RegistrationResponseJSON {
  const response = credential.response as AuthenticatorAttestationResponse

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
      transports: (response.getTransports?.() || []) as AuthenticatorTransport[],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  }
}

/**
 * Convert authentication response to JSON for server verification.
 */
export function authenticationResponseToJSON(
  credential: PublicKeyCredential
): AuthenticationResponseJSON {
  const response = credential.response as AuthenticatorAssertionResponse

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  }
}

/**
 * Create a new WebAuthn credential (registration).
 */
export async function createCredential(
  options: PublicKeyCredentialCreationOptionsJSON
): Promise<RegistrationResponseJSON> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser')
  }

  const preparedOptions = prepareRegistrationOptions(options)

  const credential = (await navigator.credentials.create({
    publicKey: preparedOptions,
  })) as PublicKeyCredential | null

  if (!credential) {
    throw new Error('Failed to create credential')
  }

  return registrationResponseToJSON(credential)
}

/**
 * Authenticate with an existing WebAuthn credential.
 */
export async function getCredential(
  options: PublicKeyCredentialRequestOptionsJSON
): Promise<AuthenticationResponseJSON> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser')
  }

  const preparedOptions = prepareAuthenticationOptions(options)

  const credential = (await navigator.credentials.get({
    publicKey: preparedOptions,
  })) as PublicKeyCredential | null

  if (!credential) {
    throw new Error('Failed to get credential')
  }

  return authenticationResponseToJSON(credential)
}

// Type definitions for WebAuthn JSON formats
export interface PublicKeyCredentialCreationOptionsJSON {
  challenge: string
  rp: {
    name: string
    id?: string
  }
  user: {
    id: string
    name: string
    displayName: string
  }
  pubKeyCredParams: { type: 'public-key'; alg: number }[]
  timeout?: number
  attestation?: AttestationConveyancePreference
  excludeCredentials?: { type: 'public-key'; id: string; transports?: AuthenticatorTransport[] }[]
  authenticatorSelection?: AuthenticatorSelectionCriteria
}

export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string
  timeout?: number
  rpId?: string
  allowCredentials?: { type: 'public-key'; id: string; transports?: AuthenticatorTransport[] }[]
  userVerification?: UserVerificationRequirement
}

export interface RegistrationResponseJSON {
  id: string
  rawId: string
  type: string
  response: {
    clientDataJSON: string
    attestationObject: string
    transports?: AuthenticatorTransport[]
  }
  clientExtensionResults: AuthenticationExtensionsClientOutputs
}

export interface AuthenticationResponseJSON {
  id: string
  rawId: string
  type: string
  response: {
    clientDataJSON: string
    authenticatorData: string
    signature: string
    userHandle: string | null
  }
  clientExtensionResults: AuthenticationExtensionsClientOutputs
}
