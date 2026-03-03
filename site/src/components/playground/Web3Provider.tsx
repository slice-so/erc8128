import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ConnectKitProvider } from "connectkit"
import { porto } from "porto/wagmi"
import { type ReactNode, useState } from "react"
import { createConfig, http, WagmiProvider } from "wagmi"
import { mainnet } from "wagmi/chains"
import { injected, walletConnect } from "wagmi/connectors"

const walletConnectProjectId =
  import.meta.env.PUBLIC_WALLETCONNECT_PROJECT_ID || "placeholder"

const config = createConfig({
  chains: [mainnet],
  connectors: [
    injected(),
    walletConnect({
      projectId: walletConnectProjectId,
      showQrModal: false
    }),
    porto()
  ],
  transports: {
    [mainnet.id]: http()
  }
})

export function Web3Provider({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => new QueryClient())

  return (
    <WagmiProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <ConnectKitProvider
          mode="dark"
          options={{
            walletConnectName: "WalletConnect"
          }}
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
