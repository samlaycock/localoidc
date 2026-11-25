// The claims editor's model: which preset, its fields' text, and the custom claims. Building it
// gives the claims to sign in (or mint tokens) with.

import { load, save } from "@/lib/storage"
import { createStore } from "@/lib/store"
import type { Claims, EditorData, Field, Identity, Preset } from "@/lib/types"

export type EditorState = {
  preset: string
  /** Each field's text (a checkbox's boolean), by claim name. */
  values: Record<string, string | boolean>
  /** Custom claims, as JSON text. */
  custom: string
  /** Access-token-only claims, as JSON text. */
  access: string
  step: number
  showAll: boolean
}

export const presetOf = (presets: Preset[], id: string) =>
  presets.find((p) => p.id === id) ?? presets[0]

function fieldText(f: Field, v: unknown): string | boolean {
  if (v === undefined || v === null) return f.kind === "bool" ? false : ""
  if (f.kind === "bool") return !!v
  if (f.kind === "json") {
    const compact = JSON.stringify(v)
    return compact.length <= 60 ? compact : JSON.stringify(v, null, 2)
  }
  return typeof v === "string" ? v : JSON.stringify(v)
}

/**
 * The editor showing an identity: its preset's fields filled from `claims` and the other claims
 * as custom ones. Without claims, it's the preset's defaults (custom claims are kept).
 */
export function loadIdentity(
  state: EditorState,
  presets: Preset[],
  presetId: string,
  claims?: Claims | null,
  access?: Claims | null
): EditorState {
  const p = presetOf(presets, presetId)
  const values: EditorState["values"] = {}
  for (const f of p.fields) {
    values[f.name] = fieldText(f, claims ? claims[f.name] : f.default)
  }
  if (!claims) return { ...state, preset: p.id, values }
  const names = new Set(p.fields.map((f) => f.name))
  const custom: Claims = {}
  for (const [k, v] of Object.entries(claims)) {
    if (names.has(k) || (k === "sub" && p.sub_from)) continue
    custom[k] = v
  }
  return {
    ...state,
    preset: p.id,
    values,
    custom: Object.keys(custom).length ? JSON.stringify(custom, null, 2) : "",
    access:
      access && Object.keys(access).length
        ? JSON.stringify(access, null, 2)
        : "",
  }
}

const HINT_KEYS = [
  "preferred_username",
  "login",
  "username",
  "nickname",
  "cognito:username",
]

/** The editor as a page first shows it. */
export function initialEditor(data: EditorData): EditorState {
  const blank: EditorState = {
    preset: data.defaultPreset,
    values: {},
    custom: "",
    access: "",
    step: data.tenantPreset ? 1 : 0,
    showAll: false,
  }
  const prev = data.previous
  let state =
    prev &&
    data.mode !== "dev" &&
    data.presets.some((p) => p.id === prev.preset)
      ? loadIdentity(
          blank,
          data.presets,
          prev.preset,
          prev.claims,
          prev.access_claims
        )
      : loadIdentity(blank, data.presets, data.defaultPreset)
  const hint = data.loginHint
  if (hint) {
    const fields = presetOf(data.presets, state.preset).fields
    const has = (n: string) => fields.some((f) => f.name === n)
    const key = hint.includes("@")
      ? has("email")
        ? "email"
        : undefined
      : HINT_KEYS.find(has)
    if (key) state = { ...state, values: { ...state.values, [key]: hint } }
  }
  return state
}

function parseObject(text: string, label: string, errors: string[]): Claims {
  if (!text.trim()) return {}
  try {
    const o: unknown = JSON.parse(text)
    if (o && typeof o === "object" && !Array.isArray(o)) return o as Claims
    errors.push(`${label}: must be a JSON object`)
  } catch (e) {
    errors.push(`${label}: ${e instanceof Error ? e.message : String(e)}`)
  }
  return {}
}

/** The claims the editor describes, and what's wrong with them. */
export function build(presets: Preset[], state: EditorState) {
  const p = presetOf(presets, state.preset)
  const claims: Claims = {}
  const errors: string[] = []
  for (const f of p.fields) {
    const v = state.values[f.name]
    if (f.kind === "bool") claims[f.name] = !!v
    else if (typeof v !== "string" || v === "") continue
    else if (f.kind === "number") {
      const n = Number(v)
      if (Number.isNaN(n)) errors.push(`${f.label}: not a number`)
      else claims[f.name] = n
    } else if (f.kind === "json") {
      if (!v.trim()) continue
      try {
        claims[f.name] = JSON.parse(v)
      } catch {
        errors.push(`${f.label}: invalid JSON`)
      }
    } else claims[f.name] = v
  }
  for (const [k, v] of Object.entries(
    parseObject(state.custom, "Custom claims", errors)
  )) {
    if (v === null) delete claims[k]
    else claims[k] = v
  }
  if (!claims.sub && p.sub_from && claims[p.sub_from] != null) {
    const from = claims[p.sub_from]
    claims.sub = typeof from === "string" ? from : JSON.stringify(from)
  }
  const access = parseObject(state.access, "Access token claims", errors)
  return { claims, access, errors }
}

/** A short name for an identity: its email, name, username or subject. */
export function describe(claims: Claims) {
  for (const key of [
    "email",
    "name",
    "preferred_username",
    "login",
    "username",
    "sub",
  ]) {
    const v = claims[key]
    if (typeof v === "string" && v) return v
  }
  return "identity"
}

// Saved identities and the last one used live in this browser.

export type SavedIdentity = Identity & { name: string }

/** The saved identities, newest first. */
export const savedIdentities = createStore<SavedIdentity[]>(
  load<SavedIdentity[]>("identities", [])
)
savedIdentities.subscribe(() => save("identities", savedIdentities.get()))

/** Saves an identity under a name, replacing one with the same name. */
export function saveIdentity(identity: SavedIdentity) {
  savedIdentities.set((list) => [
    identity,
    ...list.filter((s) => s.name !== identity.name),
  ])
}
export const lastIdentity = () => load<Identity | null>("last", null)
export const rememberLast = (identity: Identity) => save("last", identity)

/** JSON with sorted keys, to compare identities whatever their key order. */
function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`
  if (v && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stable((v as Claims)[k])}`)
      .join(",")}}`
  }
  return JSON.stringify(v)
}

export const identityKey = (i: Identity) => stable([i.preset, i.claims])
