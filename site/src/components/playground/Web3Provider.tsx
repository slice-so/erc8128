import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ConnectKitProvider } from "connectkit"
import { porto } from "porto/wagmi"
import { type ReactNode, useState } from "react"
import { createConfig, http, WagmiProvider } from "wagmi"
import { mainnet } from "wagmi/chains"
import { coinbaseWallet, walletConnect } from "wagmi/connectors"

const walletConnectProjectId = "07e58e0aa68cd2e122963d7405172add"
const alchemyUrl = `https://eth-mainnet.g.alchemy.com/v2/${import.meta.env.PUBLIC_ALCHEMY_KEY ?? ""}`

const config = createConfig({
  chains: [mainnet],
  connectors: [
    coinbaseWallet({
      appName: "ERC-8128",
      preference: {
        options: "smartWalletOnly"
      }
    }),
    walletConnect({
      projectId: walletConnectProjectId,
      showQrModal: false
    }),
    porto()
  ],
  transports: {
    [mainnet.id]: http(alchemyUrl)
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
