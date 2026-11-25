import {
  ArrowLeftIcon,
  ArrowRightIcon,
  CheckIcon,
  PencilIcon,
  SaveIcon,
  Trash2Icon,
} from "lucide-react"
import * as React from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldTitle,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemTitle,
} from "@/components/ui/item"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  build,
  describe,
  identityKey,
  lastIdentity,
  loadIdentity,
  presetOf,
  saveIdentity,
  savedIdentities,
  type EditorState,
} from "@/lib/identity"
import { useStore } from "@/lib/store"
import type {
  Claims,
  EditorData,
  Field as ClaimField,
  Identity,
  Preset,
} from "@/lib/types"
import { cn } from "@/lib/utils"

/** A preset's colour, as a dot beside its name. */
export function PresetDot({ color }: { color?: string }) {
  return (
    <span
      aria-hidden
      className="inline-block size-2 shrink-0 rounded-full bg-muted-foreground"
      style={color ? { backgroundColor: color } : undefined}
    />
  )
}

type QuickItem = {
  kind: "session" | "user" | "last" | "saved"
  label: string
  identity: Identity
}

/**
 * The claims editor: identities to reuse in one click, and a short wizard (provider → claims →
 * custom claims, and token options when minting) for a new one. `onUse` signs in (or mints)
 * with an identity; the page's own buttons use the editor's contents.
 */
export function ClaimsEditor({
  data,
  state,
  setState,
  onUse,
  options,
}: {
  data: EditorData
  state: EditorState
  setState: React.Dispatch<React.SetStateAction<EditorState>>
  onUse: (identity: Identity) => void
  /** The token generator's options, as a last step. */
  options?: React.ReactNode
}) {
  const isDev = data.mode === "dev"
  const steps = [
    "Provider",
    "Claims",
    "Custom claims",
    ...(options ? ["Token options"] : []),
  ]
  const preset = presetOf(data.presets, state.preset)
  const { errors } = build(data.presets, state)
  const edit = (identity: Identity) =>
    setState((s) => ({
      ...loadIdentity(
        s,
        data.presets,
        identity.preset,
        identity.claims,
        identity.access
      ),
      step: 1,
    }))

  return (
    <div className="flex flex-col gap-6">
      <QuickList data={data} onUse={onUse} onEdit={edit} />
      <section className="flex flex-col gap-4">
        <h2 className="text-sm font-medium">
          {isDev ? "New token" : "New identity"}
        </h2>
        <Tabs
          value={String(state.step)}
          onValueChange={(value: string) =>
            setState((s) => ({ ...s, step: Number(value) }))
          }
        >
          <TabsList variant="line" className="w-full justify-start">
            {steps.map((label, i) => (
              <TabsTrigger key={label} value={String(i)} className="flex-none">
                <span
                  className={cn(
                    "flex size-5 items-center justify-center rounded-full border text-xs tabular-nums",
                    i < state.step &&
                      "border-primary bg-primary text-primary-foreground",
                    i === state.step && "border-primary text-primary"
                  )}
                >
                  {i < state.step ? <CheckIcon className="size-3" /> : i + 1}
                </span>
                {label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        <div>
          {state.step === 0 && (
            <ProviderStep data={data} state={state} setState={setState} />
          )}
          {state.step === 1 && (
            <ClaimsStep preset={preset} state={state} setState={setState} />
          )}
          {state.step === 2 && (
            <CustomStep
              presets={data.presets}
              state={state}
              setState={setState}
            />
          )}
          {state.step === 3 && options}
        </div>
        <div className="flex items-center justify-between">
          {state.step > 0 ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setState((s) => ({ ...s, step: s.step - 1 }))}
            >
              <ArrowLeftIcon data-icon="inline-start" />
              Back
            </Button>
          ) : (
            <span />
          )}
          {state.step < steps.length - 1 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setState((s) => ({ ...s, step: s.step + 1 }))}
            >
              Next: {steps[state.step + 1]}
              <ArrowRightIcon data-icon="inline-end" />
            </Button>
          )}
        </div>
      </section>
      {errors.length > 0 && (
        <Alert variant="destructive">
          <AlertDescription>{errors.join(" · ")}</AlertDescription>
        </Alert>
      )}
    </div>
  )
}

/** The session, declared users, the last identity used and saved ones, for one-click reuse. */
function QuickList({
  data,
  onUse,
  onEdit,
}: {
  data: EditorData
  onUse: (identity: Identity) => void
  onEdit: (identity: Identity) => void
}) {
  const saved = useStore(savedIdentities)
  const isDev = data.mode === "dev"
  const items: QuickItem[] = []
  if (data.previous && !isDev) {
    items.push({
      kind: "session",
      label: "Active session",
      identity: {
        preset: data.previous.preset,
        claims: data.previous.claims,
        access: data.previous.access_claims,
      },
    })
  }
  for (const u of data.users) {
    items.push({ kind: "user", label: u.label ?? u.id, identity: u })
  }
  // "Last used" only when it isn't already offered as the session, a user or a saved identity.
  const last = lastIdentity()
  const offered = new Set([
    ...items.map((i) => identityKey(i.identity)),
    ...saved.map(identityKey),
  ])
  if (last && !offered.has(identityKey(last))) {
    items.push({ kind: "last", label: "Last used", identity: last })
  }
  for (const s of saved)
    items.push({ kind: "saved", label: s.name, identity: s })

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-medium">
        {isDev ? "Saved identities" : "Quick sign in"}
      </h2>
      {items.length ? (
        <div className="flex flex-col gap-2">
          {items.map((item) => {
            const p = presetOf(data.presets, item.identity.preset)
            const who = describe(item.identity.claims)
            const named = item.kind === "saved" || item.kind === "user"
            return (
              <Item
                key={`${item.kind}:${item.label}:${identityKey(item.identity)}`}
                variant="outline"
                size="sm"
              >
                <ItemContent className="min-w-0">
                  <ItemTitle className="w-full min-w-0">
                    <span className="truncate">
                      {named ? (
                        item.label
                      ) : (
                        <>
                          <span className="text-muted-foreground">
                            {item.label}
                          </span>{" "}
                          · {who}
                        </>
                      )}
                    </span>
                    {item.kind === "user" && (
                      <Tooltip>
                        <TooltipTrigger
                          render={<Badge variant="secondary">config</Badge>}
                        />
                        <TooltipContent>
                          Declared in localoidc.toml
                        </TooltipContent>
                      </Tooltip>
                    )}
                  </ItemTitle>
                  <ItemDescription className="flex items-center gap-1.5 text-xs">
                    <PresetDot color={p.color} />
                    <span className="truncate">
                      {p.name}
                      {named && item.label !== who ? ` · ${who}` : ""}
                    </span>
                  </ItemDescription>
                </ItemContent>
                <ItemActions>
                  <Button size="sm" onClick={() => onUse(item.identity)}>
                    {isDev ? "Generate" : "Sign in"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onEdit(item.identity)}
                  >
                    <PencilIcon data-icon="inline-start" />
                    Edit
                  </Button>
                  {item.kind === "saved" && (
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Delete ${item.label}`}
                      onClick={() =>
                        savedIdentities.set((list) =>
                          list.filter((s) => s.name !== item.label)
                        )
                      }
                    >
                      <Trash2Icon />
                    </Button>
                  )}
                </ItemActions>
              </Item>
            )
          })}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          Identities you save show up here for one-click reuse.
        </p>
      )}
    </section>
  )
}

type StepProps = {
  state: EditorState
  setState: React.Dispatch<React.SetStateAction<EditorState>>
}

function ProviderStep({
  data,
  state,
  setState,
}: StepProps & { data: EditorData }) {
  const pinned = data.tenantPreset
    ? presetOf(data.presets, data.tenantPreset)
    : null
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        Which identity provider should this look like? This sets the claim names
        and token formats.
        {pinned && ` This issuer emulates ${pinned.name}.`}
      </p>
      <RadioGroup
        aria-label="Provider"
        value={state.preset}
        onValueChange={(id: string) =>
          setState((s) => ({
            ...(id === s.preset ? s : loadIdentity(s, data.presets, id)),
            step: 1,
          }))
        }
        className="grid gap-2 sm:grid-cols-2"
      >
        {data.presets.map((p) => (
          <FieldLabel key={p.id} htmlFor={`preset-${p.id}`}>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldTitle>
                  <PresetDot color={p.color} />
                  {p.name}
                  {p.protocol === "oauth2" && (
                    <Badge variant="secondary">OAuth2</Badge>
                  )}
                </FieldTitle>
                <FieldDescription className="text-xs">
                  {p.description}
                </FieldDescription>
              </FieldContent>
              <RadioGroupItem value={p.id} id={`preset-${p.id}`} />
            </Field>
          </FieldLabel>
        ))}
      </RadioGroup>
    </div>
  )
}

function ClaimsStep({
  preset,
  state,
  setState,
}: StepProps & { preset: Preset }) {
  const common = preset.fields.filter((f) => !f.advanced)
  const advanced = preset.fields.filter((f) => f.advanced)
  const set = (name: string, value: string | boolean) =>
    setState((s) => ({ ...s, values: { ...s.values, [name]: value } }))
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        {preset.name} claims. Empty fields are left out of the token.
      </p>
      <FieldGroup className="grid gap-4 sm:grid-cols-2">
        {common.map((f) => (
          <ClaimInput
            key={f.name}
            field={f}
            value={state.values[f.name]}
            onChange={set}
          />
        ))}
      </FieldGroup>
      {advanced.length > 0 && (
        <Button
          variant="ghost"
          size="sm"
          className="self-start"
          onClick={() => setState((s) => ({ ...s, showAll: !s.showAll }))}
        >
          {state.showAll
            ? "Hide extra claims"
            : `Show all claims (${advanced.length} more)`}
        </Button>
      )}
      {state.showAll && advanced.length > 0 && (
        <FieldGroup className="grid gap-4 sm:grid-cols-2">
          {advanced.map((f) => (
            <ClaimInput
              key={f.name}
              field={f}
              value={state.values[f.name]}
              onChange={set}
            />
          ))}
        </FieldGroup>
      )}
    </div>
  )
}

function ClaimInput({
  field: f,
  value,
  onChange,
}: {
  field: ClaimField
  value: string | boolean | undefined
  onChange: (name: string, value: string | boolean) => void
}) {
  const id = `claim-${f.name.replace(/[^a-z0-9]/gi, "_")}`
  const name = (
    <code className="font-mono text-xs font-normal text-muted-foreground">
      {f.name}
    </code>
  )
  if (f.kind === "bool") {
    return (
      <Field orientation="horizontal" className="self-end">
        <Checkbox
          id={id}
          checked={value === true}
          onCheckedChange={(checked) => onChange(f.name, checked)}
        />
        <FieldContent>
          <FieldLabel htmlFor={id}>
            {f.label} {name}
          </FieldLabel>
          {f.help && <FieldDescription>{f.help}</FieldDescription>}
        </FieldContent>
      </Field>
    )
  }
  const text = typeof value === "string" ? value : ""
  return (
    <Field className={cn(f.kind === "json" && "sm:col-span-2")}>
      <FieldLabel htmlFor={id}>
        {f.label} {name}
      </FieldLabel>
      {f.kind === "json" ? (
        <Textarea
          id={id}
          rows={text.includes("\n") ? 4 : 1}
          spellCheck={false}
          className="min-h-9 font-mono text-xs"
          value={text}
          onChange={(e) => onChange(f.name, e.target.value)}
        />
      ) : (
        <Input
          id={id}
          type={f.kind === "number" ? "number" : "text"}
          spellCheck={false}
          value={text}
          onChange={(e) => onChange(f.name, e.target.value)}
        />
      )}
      {f.help && <FieldDescription>{f.help}</FieldDescription>}
    </Field>
  )
}

function CustomStep({
  presets,
  state,
  setState,
}: StepProps & { presets: Preset[] }) {
  const { claims, access } = build(presets, state)
  const preview: Claims = { ...claims }
  if (Object.keys(access).length) preview["(access token only)"] = access
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        Optional. Add or override any claim; null removes one. Reserved claims
        like aud or exp can be overridden for negative tests.
      </p>
      <FieldGroup className="grid gap-4 sm:grid-cols-2">
        <Field>
          <FieldLabel htmlFor="custom-claims">Custom claims</FieldLabel>
          <Textarea
            id="custom-claims"
            rows={6}
            spellCheck={false}
            className="font-mono text-xs"
            placeholder={
              '{\n  "https://example.com/tenant": "acme",\n  "permissions": ["read", "write"],\n  "locale": null\n}'
            }
            value={state.custom}
            onChange={(e) =>
              setState((s) => ({ ...s, custom: e.target.value }))
            }
          />
          <FieldDescription>
            ID token, userinfo and access token
          </FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="access-claims">
            Access-token-only claims
          </FieldLabel>
          <Textarea
            id="access-claims"
            rows={6}
            spellCheck={false}
            className="font-mono text-xs"
            placeholder={'{\n  "permissions": ["orders:write"]\n}'}
            value={state.access}
            onChange={(e) =>
              setState((s) => ({ ...s, access: e.target.value }))
            }
          />
        </Field>
      </FieldGroup>
      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-medium">
          Preview{" "}
          <span className="font-normal text-muted-foreground">
            (iss, aud, exp, nonce… are added by the server)
          </span>
        </h3>
        <pre className="max-h-80 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs leading-relaxed">
          {JSON.stringify(preview, null, 2)}
        </pre>
      </div>
    </div>
  )
}

/** "Save as …", beside the page's Sign in or Generate button so it's there at every step. */
export function SaveIdentity({
  presets,
  state,
}: {
  presets: Preset[]
  state: EditorState
}) {
  const [name, setName] = React.useState<string | null>(null)
  const [saved, setSaved] = React.useState(false)
  const { claims, access, errors } = build(presets, state)
  const suggested = describe(claims)

  React.useEffect(() => {
    if (!saved) return
    const timer = setTimeout(() => setSaved(false), 1400)
    return () => clearTimeout(timer)
  }, [saved])

  return (
    <div className="flex items-center gap-2">
      <Input
        aria-label="Identity name"
        placeholder="Name"
        className="w-44"
        value={name ?? suggested}
        onChange={(e) => setName(e.target.value)}
      />
      <Button
        type="button"
        variant="outline"
        disabled={errors.length > 0}
        onClick={() => {
          saveIdentity({
            name: (name ?? suggested).trim() || suggested,
            preset: state.preset,
            claims,
            access,
          })
          setSaved(true)
        }}
      >
        {saved ? (
          <CheckIcon data-icon="inline-start" />
        ) : (
          <SaveIcon data-icon="inline-start" />
        )}
        {saved ? "Saved" : "Save identity"}
      </Button>
    </div>
  )
}
