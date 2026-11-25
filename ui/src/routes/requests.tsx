import { PauseIcon, PlayIcon, SearchIcon, Trash2Icon } from "lucide-react"
import * as React from "react"
import { useSearchParams } from "react-router"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@/components/ui/empty"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
} from "@/components/ui/input-group"
import { Label } from "@/components/ui/label"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { api, message } from "@/lib/api"
import { useInfo } from "@/lib/root"
import type { RequestEntry } from "@/lib/types"
import { useUrlInput } from "@/lib/url-input"
import { cn } from "@/lib/utils"

type Page = { entries: RequestEntry[]; latest_id: number; capacity: number }

const failed = (e: RequestEntry) => !!e.error || e.status >= 400
const time = (ms: number) =>
  new Date(ms).toLocaleTimeString([], { hour12: false })

/** Recent requests to every issuer, newest first, updated live. */
export function Requests() {
  const info = useInfo()
  const [params, setParams] = useSearchParams()
  const [client, setClient] = useUrlInput("client")
  const errorsOnly = params.get("errors") === "1"
  const all = params.get("all") === "1"
  const [entries, setEntries] = React.useState<RequestEntry[]>([])
  const [paused, setPaused] = React.useState(false)
  const [open, setOpen] = React.useState<ReadonlySet<number>>(new Set())
  const lastId = React.useRef(0)

  React.useEffect(() => {
    if (paused) return
    let stopped = false
    let timer: ReturnType<typeof setTimeout>
    async function poll() {
      try {
        const data = await api<Page>(
          `/dev/api/requests?after=${lastId.current}`
        )
        if (stopped) return
        if (data.latest_id < lastId.current) {
          // localoidc restarted: ids start again from 1.
          lastId.current = 0
          setEntries([])
        }
        if (data.entries.length) {
          lastId.current = data.entries[0].id
          setEntries((current) =>
            data.entries.concat(current).slice(0, data.capacity)
          )
        }
      } catch {
        // Unreachable for now: try again.
      }
      if (!stopped) timer = setTimeout(() => void poll(), 1500)
    }
    void poll()
    return () => {
      stopped = true
      clearTimeout(timer)
    }
  }, [paused])

  const setFlag = (name: string, on: boolean) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current)
        if (on) next.set(name, "1")
        else next.delete(name)
        return next
      },
      { replace: true }
    )

  const needle = client.trim()
  const shown = entries.filter(
    (e) =>
      (all || e.category === "flow") &&
      (!needle || (e.client_id ?? "").includes(needle)) &&
      (!errorsOnly || failed(e))
  )

  async function clear() {
    try {
      await api("/dev/api/requests", { method: "DELETE" })
      setEntries([])
      setOpen(new Set())
    } catch (e) {
      toast.error(message(e))
    }
  }

  const toggle = (id: number) =>
    setOpen((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 p-6">
      <Card>
        <CardHeader>
          <CardDescription>Request inspector</CardDescription>
          <CardTitle className="text-xl">Requests</CardTitle>
          <CardAction className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPaused(!paused)}
            >
              {paused ? (
                <PlayIcon data-icon="inline-start" />
              ) : (
                <PauseIcon data-icon="inline-start" />
              )}
              {paused ? "Resume" : "Pause"}
            </Button>
            <Button variant="outline" size="sm" onClick={() => void clear()}>
              <Trash2Icon data-icon="inline-start" />
              Clear
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            The last {info.requests_capacity} requests to every issuer, newest
            first. Click one for its parameters and, if it failed, why. Secrets
            are masked and tokens shortened. Tests can read the same list from{" "}
            <code>GET {info.issuer}/dev/api/requests</code>.
          </p>
          <div className="flex flex-wrap items-center gap-4">
            <InputGroup className="w-64">
              <InputGroupAddon>
                <SearchIcon />
              </InputGroupAddon>
              <InputGroupInput
                placeholder="Filter by client_id"
                aria-label="Filter by client_id"
                value={client}
                onChange={(e) => setClient(e.target.value)}
              />
            </InputGroup>
            <Label className="font-normal">
              <Checkbox
                checked={errorsOnly}
                onCheckedChange={(on) => setFlag("errors", on)}
              />
              Errors only
            </Label>
            <Label className="font-normal">
              <Checkbox
                checked={all}
                onCheckedChange={(on) => setFlag("all", on)}
              />
              Show discovery, JWKS and dev tools
            </Label>
          </div>
          {shown.length ? (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Time</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Client</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">ms</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {shown.map((e) => (
                  <RequestRow
                    key={e.id}
                    entry={e}
                    open={open.has(e.id)}
                    onToggle={() => toggle(e.id)}
                  />
                ))}
              </TableBody>
            </Table>
          ) : (
            <Empty className="border">
              <EmptyHeader>
                <EmptyTitle>
                  {entries.length
                    ? "No requests match these filters"
                    : "No requests yet"}
                </EmptyTitle>
                <EmptyDescription>
                  {entries.length
                    ? "Change the filters to see more."
                    : `Point your app at ${info.issuer} and they'll show up here.`}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function RequestRow({
  entry: e,
  open,
  onToggle,
}: {
  entry: RequestEntry
  open: boolean
  onToggle: () => void
}) {
  const bad = failed(e)
  const params = Object.entries(e.params)
  const rows: [string, React.ReactNode][] = []
  if (e.error) {
    rows.push([
      "Why",
      <span key="why">
        <b className="font-medium text-destructive">{e.error}</b>
        {e.error_description ? ` — ${e.error_description}` : ""}
      </span>,
    ])
  }
  rows.push(["Request", <code key="req">{`${e.method} ${e.path}`}</code>])
  if (!e.error && e.outcome) rows.push(["Outcome", e.outcome])
  if (e.redirect)
    rows.push(["Redirected to", <code key="to">{e.redirect}</code>])
  if (e.authorization) {
    rows.push(["Authorization", <code key="auth">{e.authorization}</code>])
  }
  rows.push([
    "Parameters",
    params.length ? (
      <dl
        key="params"
        className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1"
      >
        {params.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="font-mono text-muted-foreground">{k}</dt>
            <dd className="font-mono break-all">{v}</dd>
          </div>
        ))}
      </dl>
    ) : (
      <span key="none" className="text-muted-foreground">
        none
      </span>
    ),
  ])
  return (
    <>
      <TableRow
        aria-expanded={open}
        className="cursor-pointer"
        onClick={onToggle}
      >
        <TableCell className="font-mono text-xs">{time(e.at)}</TableCell>
        <TableCell className="text-xs">{e.method}</TableCell>
        <TableCell className="font-mono text-xs">
          {e.outgoing && (
            <Badge
              variant="outline"
              className="mr-1.5"
              title="Sent by localoidc"
            >
              → out
            </Badge>
          )}
          {e.issuer !== "root" && (
            <Badge variant="outline" className="mr-1.5">
              {e.issuer}
            </Badge>
          )}
          {e.endpoint}
        </TableCell>
        <TableCell className="font-mono text-xs">
          {e.client_id ?? "–"}
        </TableCell>
        <TableCell
          className={cn("max-w-72 truncate text-xs", bad && "text-destructive")}
        >
          {bad && e.error ? e.error : e.outcome}
        </TableCell>
        <TableCell>
          <Badge variant={bad ? "destructive" : "secondary"}>{e.status}</Badge>
        </TableCell>
        <TableCell className="text-right text-xs tabular-nums">
          {e.duration_ms ? e.duration_ms : "<1"}
        </TableCell>
      </TableRow>
      {open && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell colSpan={7} className="whitespace-normal">
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-6 gap-y-2 py-2 text-xs">
              {rows.map(([term, value]) => (
                <div key={term} className="contents">
                  <dt className="text-muted-foreground">{term}</dt>
                  <dd className="min-w-0">{value}</dd>
                </div>
              ))}
            </dl>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}
