import { defineConfig } from "vocs"

export default defineConfig({
  rootDir: ".",
  title: "ERC-8128",
  description: "Signed HTTP Requests with Ethereum",
  iconUrl: "/favicon.svg",
  sidebar: [
    {
      text: "Introduction",
      link: "/"
    },
    {
      text: "Getting Started",
      items: [
        { text: "Installation", link: "/getting-started/installation" },
        { text: "Quick Start", link: "/getting-started/quick-start" }
      ]
    },
    {
      text: "Concepts",
      items: [
        { text: "Overview", link: "/concepts/overview" },
        { text: "Security Model", link: "/concepts/security-model" },
        { text: "Request Binding", link: "/concepts/request-binding" },
        { text: "Replay Protection", link: "/concepts/replay-protection" }
      ]
    },
    {
      text: "Guides",
      items: [
        { text: "Signing Requests", link: "/guides/signing-requests" },
        { text: "Verifying Requests", link: "/guides/verifying-requests" },
        {
          text: "Smart Contract Accounts",
          link: "/guides/smart-contract-accounts"
        }
      ]
    },
    {
      text: "API Reference",
      items: [
        { text: "signRequest", link: "/api/signRequest" },
        { text: "signedFetch", link: "/api/signedFetch" },
        { text: "createSignerClient", link: "/api/createSignerClient" },
        { text: "verifyRequest", link: "/api/verifyRequest" },
        { text: "createVerifierClient", link: "/api/createVerifierClient" },
        { text: "formatKeyId", link: "/api/formatKeyId" },
        { text: "parseKeyId", link: "/api/parseKeyId" },
        { text: "Types", link: "/api/types" }
      ]
    },
    {
      text: "CLI",
      items: [
        { text: "Overview", link: "/cli" },
        { text: "Wallet Options", link: "/cli/wallet-options" },
        { text: "Signature Options", link: "/cli/signature-options" },
        { text: "Configuration", link: "/cli/configuration" },
        { text: "Examples", link: "/cli/examples" }
      ]
    },
    {
      text: "Specification",
      link: "/specification"
    }
  ],
  socials: [
    {
      icon: "github",
      link: "https://github.com/slice-so/erc8128"
    },
    {
      icon: "x",
      link: "https://x.com/slice__so"
    }
  ]
})
