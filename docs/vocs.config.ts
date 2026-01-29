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
        { text: "createClient", link: "/api/createClient" },
        { text: "verifyRequest", link: "/api/verifyRequest" },
        { text: "formatKeyId", link: "/api/formatKeyId" },
        { text: "parseKeyId", link: "/api/parseKeyId" },
        { text: "Types", link: "/api/types" }
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
