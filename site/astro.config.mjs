import cloudflare from "@astrojs/cloudflare"
import react from "@astrojs/react"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from "astro/config"

export default defineConfig({
  output: "server",
  adapter: cloudflare(),
  integrations: [react()],
  site: "https://erc8128.org",
  build: {
    // Cloudflare Pages serves from the root
    assets: "_astro"
  },
  vite: {
    plugins: [tailwindcss()]
  }
})
