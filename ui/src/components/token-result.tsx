import { ChevronDownIcon } from "lucide-react"
import * as React from "react"

import { CodeBlock } from "@/components/code-block"
import { CopyButton } from "@/components/copy-button"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import { Textarea } from "@/components/ui/textarea"
import type { TokenResponse } from "@/lib/types"

export type Minted =
  | { ok: true; response: TokenResponse; request: Record<string, unknown> }
  | { ok: false; error: unknown }

/** A JWT's header and payload, or null for an opaque token. */
function decode(token: string) {
  const parts = token.split(".")
  if (parts.length !== 3) return null
  const part = (s: string): unknown => {
    const base64 = s.replace(/-/g, "+").replace(/_/g, "/")
    const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))
    return JSON.parse(new TextDecoder().decode(bytes))
  }
  try {
    return {
      header: part(parts[0]),
      payload: part(parts[1]) as Record<string, unknown>,
    }
  } catch {
    return null
  }
}

function Disclosure({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <Collapsible>
      <CollapsibleTrigger
        render={<Button variant="ghost" size="sm" className="group -ml-2.5" />}
      >
        {label}
        <ChevronDownIcon
          data-icon="inline-end"
          className="transition-transform group-data-panel-open:rotate-180"
        />
      </CollapsibleTrigger>
      <CollapsibleContent className="pt-2">{children}</CollapsibleContent>
    </Collapsible>
  )
}

const json = (v: unknown) => (
  <pre className="max-h-96 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs leading-relaxed">
    {JSON.stringify(v, null, 2)}
  </pre>
)

function Token({ title, token }: { title: string; token: string }) {
  const decoded = decode(token)
  const exp = decoded?.payload.exp
  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center gap-3">
        <h3 className="text-sm font-medium">{title}</h3>
        <span className="text-xs text-muted-foreground">
          {typeof exp === "number"
            ? `expires ${new Date(exp * 1000).toLocaleString()}`
            : decoded
              ? ""
              : "opaque"}
        </span>
        <CopyButton text={token} className="ml-auto" />
      </div>
      <Textarea
        readOnly
        rows={3}
        aria-label={title}
        className="field-sizing-fixed font-mono text-xs break-all"
        value={token}
        onFocus={(e) => e.target.select()}
      />
      {decoded && (
        <Disclosure label="Decoded">
          <div className="grid gap-2 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            {json(decoded.header)}
            {json(decoded.payload)}
          </div>
        </Disclosure>
      )}
    </section>
  )
}

/** The tokens just minted, and how to use them from a shell. */
export function TokenResult({
  result,
  issuer,
}: {
  result: Minted
  issuer: string
}) {
  const ref = React.useRef<HTMLDivElement>(null)
  React.useEffect(() => {
    ref.current?.scrollIntoView({ behavior: "smooth", block: "start" })
  }, [result])

  if (!result.ok) {
    return (
      <div ref={ref} className="scroll-mt-6">
        <Alert variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{json(result.error)}</AlertDescription>
        </Alert>
      </div>
    )
  }
  const { response: r, request } = result
  const exports = [
    `export ACCESS_TOKEN='${r.access_token}'`,
    r.id_token && `export ID_TOKEN='${r.id_token}'`,
    r.refresh_token && `export REFRESH_TOKEN='${r.refresh_token}'`,
  ]
    .filter(Boolean)
    .join("\n")
  const clientId =
    typeof request.client_id === "string" ? request.client_id : "localoidc-dev"
  const api = `curl -s -X POST ${issuer}/dev/api/token -H 'content-type: application/json' -d '${JSON.stringify(request).replace(/'/g, "'\\''")}'`
  return (
    <Card ref={ref} className="scroll-mt-6">
      <CardHeader>
        <CardDescription>Result</CardDescription>
        <CardTitle>Tokens</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        <Token title="Access token" token={r.access_token} />
        {r.id_token && <Token title="ID token" token={r.id_token} />}
        {r.refresh_token && (
          <Token title="Refresh token" token={r.refresh_token} />
        )}
        <section className="flex flex-col gap-3">
          <h3 className="text-sm font-medium">Use them</h3>
          <CodeBlock title="Shell exports" code={exports} />
          <CodeBlock
            title="Call userinfo"
            code={`curl -s ${r.issuer}/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"`}
          />
          {r.refresh_token && (
            <CodeBlock
              title="Refresh"
              code={`curl -s -X POST ${r.issuer}/token -d grant_type=refresh_token -d client_id=${clientId} -d refresh_token="$REFRESH_TOKEN"`}
            />
          )}
          <CodeBlock title="Reproduce via the dev API" code={api} />
          <Disclosure label="Raw response">{json(r)}</Disclosure>
        </section>
      </CardContent>
    </Card>
  )
}
