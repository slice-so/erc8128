import { defineConfig } from "astro/config"

export default defineConfig({
  output: "static",
  site: "https://erc8128.xyz",
  build: {
    // Cloudflare Pages serves from the root
    assets: "_astro"
  }
})
