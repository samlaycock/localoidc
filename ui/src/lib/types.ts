export type Claims = Record<string, unknown>

/** A claim a preset's editor shows. */
export type Field = {
  name: string
  label: string
  kind: "string" | "bool" | "number" | "json"
  default: unknown
  help?: string
  /** Tucked behind "Show all claims". */
  advanced?: boolean
}

export type Preset = {
  id: string
  name: string
  /** `oidc` or `oauth2`. */
  protocol: string
  description: string
  color: string
  fields: Field[]
  /** The claim `sub` is derived from, when the preset has no `sub` field. */
  sub_from: string | null
  default_scope: string
}

/** A user declared in localoidc.toml. */
export type User = {
  id: string
  label: string | null
  preset: string
  claims: Claims
  access: Claims
}

/** Who to sign in (or mint tokens) as. */
export type Identity = { preset: string; claims: Claims; access?: Claims }

/** What the claims editor needs: the server sends it with the sign-in and device pages. */
export type EditorData = {
  mode: "login" | "device" | "dev"
  issuer: string
  presets: Preset[]
  defaultPreset: string
  /** The preset a `/p/<preset>` issuer emulates. */
  tenantPreset: string | null
  /** This browser's session on the issuer, if any. */
  previous: { preset: string; claims: Claims; access_claims: Claims } | null
  loginHint: string | null
  users: User[]
}

export type Info = {
  version: string
  issuer: string
  prefix: string
  preset: { id: string; name: string; color: string } | null
  default_preset: string
  default_scope: string
  access_token_ttl: number
  clock: Clock
  faults_armed: number
  kid: string
  retired_keys_kept: number
  endpoints: { label: string; url: string }[]
  issuers: {
    id: string | null
    name: string
    description: string
    color?: string
    issuer: string
    prefix: string
  }[]
  fault_endpoints: string[]
  fault_errors: string[]
  max_fault_delay_ms: number
  requests_capacity: number
}

export type Clock = {
  now: number
  offset: number
  offset_text: string
  real_now: number
}

export type Fault = {
  id: number
  endpoint: string
  issuer?: string
  client_id?: string
  grant_type?: string
  error?: string
  error_description?: string
  status: number
  delay_ms: number
  /** Requests still to affect; null means until removed. */
  remaining: number | null
}

export type Session = {
  sid: string
  issuer: string
  sub: unknown
  preset: string
  clients: string[]
  auth_time: number
  expires_at: number | null
  /** The email, name or username, for display. */
  label: string | null
  /** The clients that registered a back-channel logout URI, which ending it notifies. */
  backchannel_clients: string[]
}

export type RequestEntry = {
  id: number
  at: number
  duration_ms: number
  method: string
  path: string
  issuer: string
  endpoint: string
  category: "flow" | "metadata" | "dev"
  client_id?: string
  params: Record<string, string>
  authorization?: string
  status: number
  error?: string
  error_description?: string
  outcome: string
  redirect?: string
  outgoing?: boolean
}

/** The dev token API's response. */
export type TokenResponse = {
  access_token: string
  id_token?: string
  refresh_token?: string
  token_type?: string
  expires_in?: number
  issuer: string
  preset: string
  access_token_claims?: Claims
  id_token_claims?: Claims
}

/** Which protocol page the server rendered, with what it needs. */
export type ProtocolView =
  | {
      kind: "login"
      action: string
      req: string
      client: string
      request: {
        client_id: string
        redirect_uri: string
        response_type: string
        response_mode: string
        scope: string
        state: string | null
        nonce: string | null
        code_challenge_method: string | null
        prompt: string[]
        login_hint: string | null
        audience: string[]
      }
      editor: EditorData
    }
  | { kind: "device-code"; action: string; invalid_code: string | null }
  | {
      kind: "device"
      action: string
      user_code: string
      client_id: string
      scope: string
      editor: EditorData
    }
  | { kind: "message"; title: string; detail: string }
  | { kind: "error"; status: number; title: string; detail: string }
