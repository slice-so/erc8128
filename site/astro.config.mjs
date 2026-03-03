import react from "@astrojs/react"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from "astro/config"

export default defineConfig({
  output: "static",
  integrations: [react()],
  site: "https://erc8128.org",
  build: {
    assets: "_astro"
  },
  vite: {
    plugins: [tailwindcss()]
  }
})
