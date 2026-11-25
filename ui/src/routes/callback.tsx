import { useLocation } from "react-router"

import { CodeBlock } from "@/components/code-block"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { useInfo } from "@/lib/root"

/** The built-in redirect target: shows the authorization response, to try logins without an app. */
export function Callback() {
  const info = useInfo()
  const { search, hash } = useLocation()
  const query = [...new URLSearchParams(search)]
  // Implicit and hybrid flows return their parameters in the fragment.
  const fragment = [...new URLSearchParams(hash.slice(1))]
  const code = new URLSearchParams(search).get("code")
  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-6 p-6">
      <Card>
        <CardHeader>
          <CardDescription>Callback</CardDescription>
          <CardTitle className="text-xl">Authorization response</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          <Params title="Query" params={query} />
          {fragment.length > 0 && <Params title="Fragment" params={fragment} />}
          {code && (
            <CodeBlock
              title="Exchange the code"
              code={`curl -s -X POST ${info.issuer}/token \\
  -d grant_type=authorization_code -d client_id=localoidc-demo \\
  -d redirect_uri=${info.issuer}/callback -d code=${code} | jq .`}
            />
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function Params({
  title,
  params,
}: {
  title: string
  params: [string, string][]
}) {
  return (
    <section className="flex flex-col gap-2">
      <h2 className="text-sm font-medium">{title}</h2>
      {params.length ? (
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
          {params.map(([k, v], i) => (
            <div key={`${k}-${i}`} className="contents">
              <dt className="font-mono text-xs text-muted-foreground">{k}</dt>
              <dd className="font-mono text-xs break-all">{v}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="text-sm text-muted-foreground">No parameters.</p>
      )}
    </section>
  )
}
