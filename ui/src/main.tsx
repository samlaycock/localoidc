import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { createBrowserRouter } from "react-router"
import { RouterProvider } from "react-router/dom"

import "./index.css"
import "./theme.css"
import { ThemeProvider } from "@/components/theme-provider"
import { prefix } from "@/lib/page"
import { rootLoader } from "@/lib/root"
import { Callback } from "@/routes/callback"
import { DevPage, devLoader } from "@/routes/dev"
import { Home } from "@/routes/home"
import { ProtocolPage } from "@/routes/protocol"
import { Requests } from "@/routes/requests"
import { Loading, Root, RouteError } from "@/routes/root"

const router = createBrowserRouter(
  [
    {
      id: "root",
      path: "/",
      loader: rootLoader,
      Component: Root,
      ErrorBoundary: RouteError,
      HydrateFallback: Loading,
      children: [
        { index: true, Component: Home },
        {
          path: "dev",
          loader: devLoader,
          Component: DevPage,
          ErrorBoundary: RouteError,
        },
        { path: "dev/requests", Component: Requests },
        { path: "callback", Component: Callback },
        // The protocol's pages (sign-in, device approval, errors), which the server describes.
        { path: "*", Component: ProtocolPage },
      ],
    },
  ],
  // Every issuer serves the app: the root one at `/`, a provider's at `/p/<preset>`.
  { basename: prefix || "/" }
)

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider storageKey="localoidc.theme">
      <RouterProvider router={router} />
    </ThemeProvider>
  </StrictMode>
)
