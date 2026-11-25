import { KeyRoundIcon, LogInIcon } from "lucide-react"
import { Link } from "react-router"

import { PresetDot } from "@/components/claims-editor"
import { CodeBlock } from "@/components/code-block"
import { CopyButton } from "@/components/copy-button"
import { Button, buttonVariants } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Item,
  ItemContent,
  ItemDescription,
  ItemTitle,
} from "@/components/ui/item"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { useInfo } from "@/lib/root"
import { cn } from "@/lib/utils"

/** The issuer: where to point an app, its endpoints, and the other issuers. */
export function Home() {
  const info = useInfo()
  const dev = `${info.issuer}/dev/api/token`
  const login = `${info.prefix}/authorize?${new URLSearchParams({
    client_id: "localoidc-demo",
    redirect_uri: `${info.issuer}/callback`,
    response_type: "code",
    scope: "openid profile email",
    state: "demo",
  })}`
  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 p-6">
      <Card>
        <CardHeader>
          <CardDescription>Local identity provider</CardDescription>
          <CardTitle className="flex flex-wrap items-center gap-x-2 text-2xl">
            Issuer
            <span className="font-mono text-primary">{info.issuer}</span>
            <CopyButton text={info.issuer} variant="ghost" />
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">
            Point your app at this issuer. Any <code>client_id</code>,{" "}
            <code>client_secret</code> and <code>redirect_uri</code> is accepted
            unless declared in <code>localoidc.toml</code>. Signing in shows a
            claims editor instead of a password prompt.
          </p>
          <div className="flex gap-2">
            <Link to="/dev" className={buttonVariants()}>
              <KeyRoundIcon data-icon="inline-start" />
              Open token generator
            </Link>
            <Button
              variant="outline"
              render={<a href={login} />}
              nativeButton={false}
            >
              <LogInIcon data-icon="inline-start" />
              Try a login
            </Button>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Endpoints</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableBody>
              {info.endpoints.map((e) => (
                <TableRow key={e.label}>
                  <TableCell className="w-60 text-muted-foreground">
                    {e.label}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{e.url}</TableCell>
                  <TableCell className="w-20 text-right">
                    <CopyButton text={e.url} variant="ghost" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Quick start</CardTitle>
        </CardHeader>
        <CardContent>
          <CodeBlock
            title="Mint tokens with curl"
            code={`curl -s '${dev}?email=me@example.com&roles=["admin"]' | jq .
curl -s -X POST ${dev} -H 'content-type: application/json' \\
  -d '{"preset":"google","claims":{"email":"me@example.com","hd":"acme.dev"}}'`}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Issuers</CardTitle>
          <CardDescription>
            Each provider preset is also served as its own issuer, with
            provider-specific claim shapes and endpoint aliases.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {info.issuers.map((t) => {
            const current = t.issuer === info.issuer
            return (
              <Item
                key={t.issuer}
                variant="outline"
                size="sm"
                className={cn(current && "border-primary/40 bg-primary/5")}
                render={
                  <a
                    href={t.prefix || "/"}
                    aria-current={current ? "page" : undefined}
                  />
                }
              >
                <ItemContent className="min-w-0">
                  <ItemTitle>
                    <PresetDot color={t.color} />
                    {t.name}
                  </ItemTitle>
                  <ItemDescription className="text-xs">
                    {t.description}
                  </ItemDescription>
                  <code className="truncate font-mono text-xs text-muted-foreground">
                    {t.issuer}
                  </code>
                </ItemContent>
              </Item>
            )
          })}
        </CardContent>
      </Card>
    </div>
  )
}
