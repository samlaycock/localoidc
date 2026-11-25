import {
  ClockIcon,
  KeyRoundIcon,
  PlusIcon,
  RotateCcwIcon,
  Trash2Icon,
  WandSparklesIcon,
  XIcon,
} from "lucide-react"
import * as React from "react"
import { useLoaderData, useLocation, useRevalidator } from "react-router"
import { toast } from "sonner"

import { ClaimsEditor, SaveIdentity } from "@/components/claims-editor"
import { TokenResult, type Minted } from "@/components/token-result"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemTitle,
} from "@/components/ui/item"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { ApiError, api, message } from "@/lib/api"
import {
  build,
  initialEditor,
  loadIdentity,
  rememberLast,
  type EditorState,
} from "@/lib/identity"
import { useInfo } from "@/lib/root"
import type {
  EditorData,
  Fault,
  Identity,
  Info,
  Preset,
  Session,
  TokenResponse,
  User,
} from "@/lib/types"

export async function devLoader() {
  const [presets, users, faults, sessions] = await Promise.all([
    api<Preset[]>("/dev/api/presets"),
    api<User[]>("/dev/api/users"),
    api<Fault[]>("/dev/api/faults"),
    api<Session[]>("/dev/api/sessions"),
  ])
  return { presets, users, faults, sessions }
}

type DevData = Awaited<ReturnType<typeof devLoader>>

/** The token generator, and the clock, faults, sessions and signing key controls. */
export function DevPage() {
  const info = useInfo()
  const data = useLoaderData<DevData>()
  const { hash } = useLocation()

  // The warning banners link to the sections here.
  React.useEffect(() => {
    if (hash) document.getElementById(hash.slice(1))?.scrollIntoView()
  }, [hash])

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 p-6">
      <TokenGenerator info={info} presets={data.presets} users={data.users} />
      <ClockCard info={info} />
      <FaultsCard info={info} faults={data.faults} />
      <SessionsCard info={info} sessions={data.sessions} />
      <KeyCard info={info} />
    </div>
  )
}

type Options = {
  client: string
  audience: string
  scope: string
  ttl: string
  nonce: string
  idToken: boolean
  refresh: boolean
}

function TokenGenerator({
  info,
  presets,
  users,
}: {
  info: Info
  presets: Preset[]
  users: User[]
}) {
  const [editorData] = React.useState<EditorData>(() => ({
    mode: "dev",
    issuer: info.issuer,
    presets,
    defaultPreset: info.default_preset,
    tenantPreset: info.preset?.id ?? null,
    previous: null,
    loginHint: null,
    users,
  }))
  const [state, setState] = React.useState(() => initialEditor(editorData))
  const [options, setOptions] = React.useState<Options>({
    client: "localoidc-dev",
    audience: "",
    scope: info.default_scope,
    ttl: String(info.access_token_ttl),
    nonce: "",
    idToken: true,
    refresh: true,
  })
  const [busy, setBusy] = React.useState(false)
  const [result, setResult] = React.useState<Minted | null>(null)
  const { errors } = build(presets, state)

  async function generate(editor: EditorState) {
    const { claims, access, errors } = build(presets, editor)
    if (errors.length) return
    rememberLast({ preset: editor.preset, claims, access })
    const request = {
      preset: editor.preset,
      client_id: options.client || undefined,
      audience: options.audience || undefined,
      scope: options.scope,
      expires_in: Number(options.ttl) || undefined,
      nonce: options.nonce || undefined,
      id_token: options.idToken,
      refresh_token: options.refresh,
      defaults: false,
      claims,
      access_token_claims: access,
    }
    setBusy(true)
    try {
      const response = await api<TokenResponse>("/dev/api/token", {
        method: "POST",
        body: request,
      })
      setResult({ ok: true, response, request })
    } catch (e) {
      setResult({
        ok: false,
        error: e instanceof ApiError && e.data ? e.data : { error: message(e) },
      })
    } finally {
      setBusy(false)
    }
  }

  function use(identity: Identity) {
    const next = loadIdentity(
      state,
      presets,
      identity.preset,
      identity.claims,
      identity.access
    )
    setState(next)
    void generate(next)
  }

  const set = <K extends keyof Options>(key: K, value: Options[K]) =>
    setOptions((o) => ({ ...o, [key]: value }))

  const optionsStep = (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        Who the tokens are for and how long they last.
      </p>
      <FieldGroup className="grid gap-4 sm:grid-cols-2">
        <Field>
          <FieldLabel htmlFor="dev-client">client_id</FieldLabel>
          <Input
            id="dev-client"
            value={options.client}
            onChange={(e) => set("client", e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="dev-audience">Access token audience</FieldLabel>
          <Input
            id="dev-audience"
            placeholder="defaults to client_id"
            value={options.audience}
            onChange={(e) => set("audience", e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="dev-scope">Scope</FieldLabel>
          <Input
            id="dev-scope"
            value={options.scope}
            onChange={(e) => set("scope", e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="dev-ttl">Lifetime (s)</FieldLabel>
          <Input
            id="dev-ttl"
            type="number"
            value={options.ttl}
            onChange={(e) => set("ttl", e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="dev-nonce">Nonce</FieldLabel>
          <Input
            id="dev-nonce"
            placeholder="optional"
            value={options.nonce}
            onChange={(e) => set("nonce", e.target.value)}
          />
        </Field>
        <div className="flex flex-col justify-end gap-3">
          <Field orientation="horizontal">
            <Checkbox
              id="dev-idtoken"
              checked={options.idToken}
              onCheckedChange={(on) => set("idToken", on)}
            />
            <FieldLabel htmlFor="dev-idtoken">ID token</FieldLabel>
          </Field>
          <Field orientation="horizontal">
            <Checkbox
              id="dev-refresh"
              checked={options.refresh}
              onCheckedChange={(on) => set("refresh", on)}
            />
            <FieldLabel htmlFor="dev-refresh">Refresh token</FieldLabel>
          </Field>
        </div>
      </FieldGroup>
    </div>
  )

  return (
    <>
      <Card>
        <CardHeader>
          <CardDescription>Token generator</CardDescription>
          <CardTitle className="text-xl">
            Mint tokens for{" "}
            <span className="font-mono text-primary">{info.issuer}</span>
          </CardTitle>
          <CardDescription>
            Generate access, ID and refresh tokens without running a login flow.
            Scripts and tests can use the same thing via{" "}
            <code>POST {info.issuer}/dev/api/token</code>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ClaimsEditor
            data={editorData}
            state={state}
            setState={setState}
            onUse={use}
            options={optionsStep}
          />
        </CardContent>
        <CardFooter className="flex flex-wrap justify-between gap-3 border-t">
          <Button
            disabled={busy || errors.length > 0}
            onClick={() => void generate(state)}
          >
            <WandSparklesIcon data-icon="inline-start" />
            Generate tokens
          </Button>
          <SaveIdentity presets={presets} state={state} />
        </CardFooter>
      </Card>
      {result && <TokenResult result={result} issuer={info.issuer} />}
    </>
  )
}

const AMOUNT_KEY = "localoidc.clockAmount"

function ClockCard({ info }: { info: Info }) {
  const { revalidate } = useRevalidator()
  const [amount, setAmount] = React.useState(() => {
    try {
      return sessionStorage.getItem(AMOUNT_KEY) ?? "1h"
    } catch {
      return "1h"
    }
  })
  const offset = info.clock.offset

  async function shift(body: object) {
    try {
      const clock = await api<Info["clock"]>("/dev/api/clock", {
        method: "POST",
        body,
      })
      try {
        sessionStorage.setItem(AMOUNT_KEY, amount)
      } catch {
        // Not kept.
      }
      toast(
        clock.offset
          ? `The clock is now ${clock.offset_text} ${clock.offset > 0 ? "ahead of" : "behind"} real time`
          : "The clock is back on real time"
      )
      await revalidate()
    } catch (e) {
      toast.error(`Changing the clock failed: ${message(e)}`)
    }
  }
  const by = () => amount.trim().replace(/^[+-]/, "")

  return (
    <Card id="clock" className="scroll-mt-6">
      <CardHeader>
        <CardDescription className="flex items-center gap-1.5">
          <ClockIcon className="size-3.5" />
          Clock
        </CardDescription>
        <CardTitle>
          {offset === 0 ? (
            "The clock runs on real time"
          ) : (
            <>
              The clock is{" "}
              <span className="text-primary">{info.clock.offset_text}</span>{" "}
              {offset > 0 ? "ahead of" : "behind"} real time
            </>
          )}
        </CardTitle>
        <CardDescription>
          Shift it to expire refresh tokens, sessions and codes without waiting,
          or to simulate an identity provider whose clock is off. Scripts can
          use <code>POST {info.issuer}/dev/api/clock</code>.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-2">
        <Input
          aria-label="Duration, e.g. 15m, 2h, 31d"
          className="w-28 font-mono"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
        <Button variant="outline" onClick={() => void shift({ advance: by() })}>
          Move forward
        </Button>
        <Button
          variant="outline"
          onClick={() => void shift({ advance: `-${by()}` })}
        >
          Move back
        </Button>
        <Button
          variant="ghost"
          disabled={offset === 0}
          onClick={() => void shift({ reset: true })}
        >
          <RotateCcwIcon data-icon="inline-start" />
          Reset to real time
        </Button>
      </CardContent>
    </Card>
  )
}

function describeFault(f: Fault) {
  const parts = [
    f.error
      ? f.endpoint === "authorize"
        ? f.error
        : `${f.error} (${f.status})`
      : "no error",
  ]
  if (f.delay_ms > 0) parts.push(`after ${f.delay_ms} ms`)
  if (f.client_id) parts.push(`client ${f.client_id}`)
  if (f.grant_type) parts.push(`grant ${f.grant_type}`)
  if (f.issuer) parts.push(`issuer ${f.issuer}`)
  parts.push(
    f.remaining == null
      ? "until removed"
      : f.remaining === 1
        ? "next request"
        : `next ${f.remaining} requests`
  )
  return parts.join(" · ")
}

function FaultsCard({ info, faults }: { info: Info; faults: Fault[] }) {
  const { revalidate } = useRevalidator()
  const [endpoint, setEndpoint] = React.useState(info.fault_endpoints[0])
  const [error, setError] = React.useState("")
  const [client, setClient] = React.useState("")
  const [delay, setDelay] = React.useState("0")
  const [count, setCount] = React.useState("1")
  const [always, setAlways] = React.useState(false)

  async function change(method: string, path: string, body?: object) {
    try {
      await api(path, { method, body })
      await revalidate()
    } catch (e) {
      toast.error(`Changing faults failed: ${message(e)}`)
    }
  }

  function arm() {
    const body: Record<string, unknown> = { endpoint }
    if (error.trim()) body.error = error.trim()
    if (client.trim()) body.client_id = client.trim()
    if (Number(delay)) body.delay_ms = Number(delay)
    if (always) body.always = true
    else body.count = Math.max(1, Number(count) || 1)
    void change("POST", "/dev/api/faults", body)
  }

  const endpoints = info.fault_endpoints.map((e) => ({ label: e, value: e }))
  return (
    <Card id="faults" className="scroll-mt-6">
      <CardHeader>
        <CardDescription>Faults</CardDescription>
        <CardTitle>
          {faults.length ? `${faults.length} armed` : "No faults armed"}
        </CardTitle>
        <CardDescription>
          Make the next matching requests fail on purpose, or respond slowly, to
          test your app's error handling. Authorization errors are redirected
          back to the client like real ones. Scripts can use{" "}
          <code>POST {info.issuer}/dev/api/faults</code>.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {faults.length > 0 && (
          <div className="flex flex-col gap-2">
            {faults.map((f) => (
              <Item key={f.id} variant="outline" size="sm">
                <ItemContent>
                  <ItemTitle className="font-mono">{f.endpoint}</ItemTitle>
                  <ItemDescription className="text-xs">
                    {describeFault(f)}
                  </ItemDescription>
                </ItemContent>
                <ItemActions>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      void change("DELETE", `/dev/api/faults/${f.id}`)
                    }
                  >
                    <XIcon data-icon="inline-start" />
                    Remove
                  </Button>
                </ItemActions>
              </Item>
            ))}
          </div>
        )}
        <FieldGroup className="grid gap-4 sm:grid-cols-3">
          <Field>
            <FieldLabel>Endpoint</FieldLabel>
            <Select
              items={endpoints}
              value={endpoint}
              onValueChange={(v) => v && setEndpoint(v)}
            >
              <SelectTrigger className="w-full font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {endpoints.map((e) => (
                  <SelectItem
                    key={e.value}
                    value={e.value}
                    className="font-mono"
                  >
                    {e.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel htmlFor="fault-error">Error</FieldLabel>
            <Input
              id="fault-error"
              list="fault-errors"
              placeholder="server_error"
              className="font-mono"
              value={error}
              onChange={(e) => setError(e.target.value)}
            />
            <datalist id="fault-errors">
              {info.fault_errors.map((e) => (
                <option key={e} value={e} />
              ))}
            </datalist>
          </Field>
          <Field>
            <FieldLabel htmlFor="fault-client">Client</FieldLabel>
            <Input
              id="fault-client"
              placeholder="any client"
              value={client}
              onChange={(e) => setClient(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="fault-delay">Delay (ms)</FieldLabel>
            <Input
              id="fault-delay"
              type="number"
              min={0}
              max={info.max_fault_delay_ms}
              value={delay}
              onChange={(e) => setDelay(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="fault-count">Times</FieldLabel>
            <Input
              id="fault-count"
              type="number"
              min={1}
              disabled={always}
              value={count}
              onChange={(e) => setCount(e.target.value)}
            />
          </Field>
          <Field orientation="horizontal" className="self-end pb-2">
            <Checkbox
              id="fault-always"
              checked={always}
              onCheckedChange={setAlways}
            />
            <FieldLabel htmlFor="fault-always">Until removed</FieldLabel>
          </Field>
        </FieldGroup>
      </CardContent>
      <CardFooter className="gap-2 border-t">
        <Button variant="outline" onClick={arm}>
          <PlusIcon data-icon="inline-start" />
          Arm fault
        </Button>
        <Button
          variant="ghost"
          disabled={!faults.length}
          onClick={() => void change("DELETE", "/dev/api/faults")}
        >
          <Trash2Icon data-icon="inline-start" />
          Remove all
        </Button>
      </CardFooter>
    </Card>
  )
}

type Delivery = { client_id: string; error?: string }

function SessionsCard({ info, sessions }: { info: Info; sessions: Session[] }) {
  const { revalidate } = useRevalidator()
  const [ending, setEnding] = React.useState<string | null>(null)

  async function end(sid: string) {
    setEnding(sid)
    try {
      const result = await api<{ deliveries: Delivery[] }>(
        `/dev/api/sessions/${encodeURIComponent(sid)}`,
        { method: "DELETE" }
      )
      const failed = result.deliveries.filter((d) => d.error)
      if (failed.length) {
        toast.error(
          `Session ended, but ${failed.length} logout ${failed.length === 1 ? "delivery" : "deliveries"} failed`,
          {
            description: failed
              .map((d) => `${d.client_id}: ${d.error}`)
              .join("\n"),
          }
        )
      } else {
        toast("Session ended")
      }
      await revalidate()
    } catch (e) {
      toast.error(`Ending the session failed: ${message(e)}`)
    } finally {
      setEnding(null)
    }
  }

  return (
    <Card id="sessions" className="scroll-mt-6">
      <CardHeader>
        <CardDescription>Sessions</CardDescription>
        <CardTitle>
          {sessions.length
            ? `${sessions.length} active ${sessions.length === 1 ? "session" : "sessions"}`
            : "No active sessions"}
        </CardTitle>
        <CardDescription>
          Browser sessions on every issuer. Ending one is like the user logging
          out elsewhere: clients that used it and registered a{" "}
          <code>backchannel_logout_uri</code> get a logout token, and its
          refresh tokens stop working. Scripts can use{" "}
          <code>DELETE {info.issuer}/dev/api/sessions/&lt;sid&gt;</code>.
        </CardDescription>
      </CardHeader>
      {sessions.length > 0 && (
        <CardContent className="flex flex-col gap-2">
          {sessions.map((s) => (
            <Item key={s.sid} variant="outline" size="sm">
              <ItemContent className="min-w-0">
                <ItemTitle className="flex-wrap">
                  {s.label ?? "unknown"}
                  <span className="font-normal text-muted-foreground">
                    · {s.preset} ·
                  </span>
                  {s.clients.length ? (
                    s.clients.map((c) =>
                      s.backchannel_clients.includes(c) ? (
                        <Badge
                          key={c}
                          variant="secondary"
                          className="font-mono"
                        >
                          {c}
                        </Badge>
                      ) : (
                        <Tooltip key={c}>
                          <TooltipTrigger
                            render={
                              <Badge
                                variant="outline"
                                className="font-mono text-muted-foreground"
                              >
                                {c}
                              </Badge>
                            }
                          />
                          <TooltipContent>
                            No backchannel_logout_uri registered: won't be
                            notified
                          </TooltipContent>
                        </Tooltip>
                      )
                    )
                  ) : (
                    <span className="font-normal text-muted-foreground">
                      no clients
                    </span>
                  )}
                </ItemTitle>
                <ItemDescription className="truncate font-mono text-xs">
                  sid {s.sid} · {s.issuer}
                </ItemDescription>
              </ItemContent>
              <ItemActions>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={ending === s.sid}
                  onClick={() => void end(s.sid)}
                >
                  End session
                </Button>
              </ItemActions>
            </Item>
          ))}
        </CardContent>
      )}
    </Card>
  )
}

function KeyCard({ info }: { info: Info }) {
  const { revalidate } = useRevalidator()
  const [busy, setBusy] = React.useState(false)

  async function rotate() {
    setBusy(true)
    try {
      const result = await api<{ kid: string }>("/dev/api/rotate-keys", {
        method: "POST",
      })
      toast(`Rotated: new key ${result.kid}`)
      await revalidate()
    } catch (e) {
      toast.error(`Key rotation failed: ${message(e)}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardDescription className="flex items-center gap-1.5">
          <KeyRoundIcon className="size-3.5" />
          Signing key
        </CardDescription>
        <CardTitle className="font-mono">{info.kid}</CardTitle>
        <CardDescription>
          Tokens are signed with this key. Rotating creates a new key; the
          previous {info.retired_keys_kept} stay in the JWKS so tokens already
          issued keep verifying. Scripts can use{" "}
          <code>POST {info.issuer}/dev/api/rotate-keys</code>.
        </CardDescription>
      </CardHeader>
      <CardFooter className="border-t">
        <Button variant="outline" disabled={busy} onClick={() => void rotate()}>
          <RotateCcwIcon data-icon="inline-start" />
          Rotate signing key
        </Button>
      </CardFooter>
    </Card>
  )
}
