import { ChevronDownIcon } from "lucide-react"
import * as React from "react"
import { flushSync } from "react-dom"
import { useLocation } from "react-router"

import { ClaimsEditor, SaveIdentity } from "@/components/claims-editor"
import { Alert, AlertDescription } from "@/components/ui/alert"
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
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import { Field, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  build,
  initialEditor,
  loadIdentity,
  rememberLast,
} from "@/lib/identity"
import { initialPath, page } from "@/lib/page"
import type { EditorData, Identity, ProtocolView } from "@/lib/types"
import { NotFound } from "@/routes/not-found"

/**
 * The protocol's pages: the server decides which (sign-in, device approval, sign-out, an error)
 * and sends what it needs. Leaving the page and coming back shows it again; any other address
 * the app doesn't know is not found.
 */
export function ProtocolPage() {
  const { pathname } = useLocation()
  const view = page.view
  if (!view || pathname !== stripPrefix(initialPath)) return <NotFound />
  switch (view.kind) {
    case "login":
      return <LoginView view={view} />
    case "device-code":
      return <DeviceCodeView view={view} />
    case "device":
      return <DeviceView view={view} />
    case "message":
      return (
        <MessageView
          eyebrow="localoidc"
          title={view.title}
          detail={view.detail}
        />
      )
    case "error":
      return (
        <MessageView
          eyebrow={`Error ${view.status}`}
          title={view.title}
          detail={view.detail}
          error
        />
      )
  }
}

const stripPrefix = (path: string) =>
  page.prefix && path.startsWith(page.prefix)
    ? path.slice(page.prefix.length) || "/"
    : path

function MessageView({
  eyebrow,
  title,
  detail,
  error = false,
}: {
  eyebrow: string
  title: string
  detail: string
  error?: boolean
}) {
  return (
    <div className="mx-auto max-w-lg p-6 pt-16">
      <Card>
        <CardHeader>
          <CardDescription className={error ? "text-destructive" : undefined}>
            {eyebrow}
          </CardDescription>
          <CardTitle className="text-xl">{title}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{detail}</p>
        </CardContent>
      </Card>
    </div>
  )
}

/**
 * A sign-in (or device approval) form: the claims editor, with the server's hidden fields and
 * Approve / Deny buttons. Submitting it is a real form post, so the server redirects back to the
 * app as it would for any login.
 */
function EditorForm({
  data,
  action,
  hidden,
  approveLabel,
  denyLabel,
}: {
  data: EditorData
  action: string
  hidden: Record<string, string>
  approveLabel: string
  denyLabel: string
}) {
  const [state, setState] = React.useState(() => initialEditor(data))
  const form = React.useRef<HTMLFormElement>(null)
  const approve = React.useRef<HTMLButtonElement>(null)
  const { claims, access, errors } = build(data.presets, state)

  /** Sign in as one of the quick identities. */
  function use(identity: Identity) {
    flushSync(() =>
      setState((s) =>
        loadIdentity(
          s,
          data.presets,
          identity.preset,
          identity.claims,
          identity.access
        )
      )
    )
    form.current?.requestSubmit(approve.current)
  }

  return (
    <form
      ref={form}
      method="post"
      action={action}
      onSubmit={(e) => {
        const submitter = (e.nativeEvent as SubmitEvent)
          .submitter as HTMLButtonElement | null
        if (submitter?.value === "deny") return
        if (errors.length) {
          e.preventDefault()
          return
        }
        rememberLast({ preset: state.preset, claims, access })
      }}
    >
      <Card>
        {Object.entries(hidden).map(([name, value]) => (
          <input key={name} type="hidden" name={name} value={value} />
        ))}
        <input type="hidden" name="preset" value={state.preset} />
        <input type="hidden" name="claims" value={JSON.stringify(claims)} />
        <input
          type="hidden"
          name="access_claims"
          value={JSON.stringify(access)}
        />
        <CardContent>
          <ClaimsEditor
            data={data}
            state={state}
            setState={setState}
            onUse={use}
          />
        </CardContent>
        <CardFooter className="flex flex-wrap justify-between gap-3 border-t">
          <div className="flex gap-2">
            <Button ref={approve} type="submit" name="action" value="approve">
              {approveLabel}
            </Button>
            <Button type="submit" name="action" value="deny" variant="outline">
              {denyLabel}
            </Button>
          </div>
          <SaveIdentity presets={data.presets} state={state} />
        </CardFooter>
      </Card>
    </form>
  )
}

function Details({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
      {rows.map(([term, value]) => (
        <div key={term} className="contents">
          <dt className="font-mono text-xs text-muted-foreground">{term}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

const code = (v: string) => <code className="font-mono text-xs">{v}</code>

function Scopes({ scope }: { scope: string }) {
  const scopes = scope.split(/\s+/).filter(Boolean)
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.length ? (
        scopes.map((s) => (
          <Badge key={s} variant="secondary" className="font-mono">
            {s}
          </Badge>
        ))
      ) : (
        <Badge variant="outline" className="text-muted-foreground">
          no scopes
        </Badge>
      )}
    </div>
  )
}

function LoginView({
  view,
}: {
  view: Extract<ProtocolView, { kind: "login" }>
}) {
  const r = view.request
  const rows: [string, React.ReactNode][] = [
    ["client_id", code(r.client_id)],
    ["redirect_uri", code(r.redirect_uri)],
    ["response_type", code(r.response_type)],
    ["response_mode", code(r.response_mode)],
    ["scope", <Scopes key="scope" scope={r.scope} />],
  ]
  if (r.state) rows.push(["state", code(r.state)])
  if (r.nonce) rows.push(["nonce", code(r.nonce)])
  rows.push([
    "PKCE",
    r.code_challenge_method ? (
      <Badge>{r.code_challenge_method}</Badge>
    ) : (
      <Badge variant="outline" className="text-muted-foreground">
        not used
      </Badge>
    ),
  ])
  if (r.prompt.length) rows.push(["prompt", code(r.prompt.join(" "))])
  if (r.login_hint) rows.push(["login_hint", code(r.login_hint)])
  if (r.audience.length) rows.push(["audience", code(r.audience.join(" "))])
  rows.push(["issuer", code(view.editor.issuer)])

  return (
    <div className="mx-auto grid max-w-6xl items-start gap-6 p-6 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
      <Card>
        <CardHeader>
          <CardDescription>Authorization request</CardDescription>
          <CardTitle className="text-xl">
            Sign in to <span className="text-primary">{view.client}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Scopes scope={r.scope} />
          <Collapsible>
            <CollapsibleTrigger
              render={
                <Button variant="ghost" size="sm" className="group -ml-2.5" />
              }
            >
              Request details
              <ChevronDownIcon
                data-icon="inline-end"
                className="transition-transform group-data-panel-open:rotate-180"
              />
            </CollapsibleTrigger>
            <CollapsibleContent className="pt-3">
              <Details rows={rows} />
            </CollapsibleContent>
          </Collapsible>
        </CardContent>
      </Card>
      <EditorForm
        data={view.editor}
        action={view.action}
        hidden={{ req: view.req }}
        approveLabel="Sign in"
        denyLabel="Deny access"
      />
    </div>
  )
}

function DeviceCodeView({
  view,
}: {
  view: Extract<ProtocolView, { kind: "device-code" }>
}) {
  return (
    <div className="mx-auto max-w-lg p-6 pt-16">
      <Card>
        <CardHeader>
          <CardDescription>Device sign-in</CardDescription>
          <CardTitle className="text-xl">
            Enter the code shown on your device
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {view.invalid_code && (
            <Alert variant="destructive">
              <AlertDescription>
                Code <code className="font-mono">{view.invalid_code}</code> is
                invalid or has expired.
              </AlertDescription>
            </Alert>
          )}
          <form
            method="get"
            action={view.action}
            className="flex items-end gap-2"
          >
            <Field className="flex-1">
              <FieldLabel htmlFor="user-code">Code</FieldLabel>
              <Input
                id="user-code"
                name="user_code"
                placeholder="XXXX-XXXX"
                autoComplete="off"
                autoFocus
                required
                className="font-mono uppercase"
              />
            </Field>
            <Button type="submit">Continue</Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}

function DeviceView({
  view,
}: {
  view: Extract<ProtocolView, { kind: "device" }>
}) {
  return (
    <div className="mx-auto grid max-w-6xl items-start gap-6 p-6 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
      <Card>
        <CardHeader>
          <CardDescription>Device authorization</CardDescription>
          <CardTitle className="text-xl">
            Approve <span className="text-primary">{view.client_id}</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Details
            rows={[
              [
                "user_code",
                <code key="code" className="font-mono text-lg font-semibold">
                  {view.user_code}
                </code>,
              ],
              ["client_id", code(view.client_id)],
              ["scope", <Scopes key="scope" scope={view.scope} />],
              ["issuer", code(view.editor.issuer)],
            ]}
          />
        </CardContent>
      </Card>
      <EditorForm
        data={view.editor}
        action={view.action}
        hidden={{ user_code: view.user_code }}
        approveLabel="Approve device"
        denyLabel="Deny"
      />
    </div>
  )
}
