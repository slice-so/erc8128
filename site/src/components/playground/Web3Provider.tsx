import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ConnectKitProvider, getDefaultConfig } from "connectkit"
import { porto } from "porto/wagmi"
import { type ReactNode, useState } from "react"
import { createConfig, http, WagmiProvider } from "wagmi"
import { mainnet } from "wagmi/chains"
import { injected, walletConnect } from "wagmi/connectors"

function ambireProvider() {
  if (typeof window === "undefined") return undefined

  const ethereum = (window as any).ethereum
  if (!ethereum) return undefined

  if (Array.isArray(ethereum.providers)) {
    return ethereum.providers.find((provider: any) => provider?.isAmbire)
  }

  if (ethereum?.isAmbire) return ethereum
  return undefined
}

const config = createConfig(
  getDefaultConfig({
    chains: [mainnet],
    connectors: [
      injected(),
      walletConnect({
        projectId:
          import.meta.env.PUBLIC_WALLETCONNECT_PROJECT_ID || "placeholder"
      }),
      injected({
        target: {
          id: "ambire",
          name: "Ambire Wallet",
          provider: ambireProvider
        }
      }),
      porto()
    ],
    transports: {
      [mainnet.id]: http()
    },
    walletConnectProjectId:
      import.meta.env.PUBLIC_WALLETCONNECT_PROJECT_ID || "placeholder",
    appName: "ERC-8128 Playground",
    appDescription: "Sign and verify HTTP requests with your Ethereum wallet",
    appUrl: "https://erc8128.org"
  })
)

export function Web3Provider({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => new QueryClient())

  return (
    <WagmiProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <ConnectKitProvider
          mode="dark"
          customTheme={{
            "--ck-font-family": "var(--font-mono)",
            "--ck-border-radius": "0px",
            "--ck-overlay-background": "rgba(0, 0, 0, 0.8)"
          }}
        >
          {children}
        </ConnectKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  )
}
