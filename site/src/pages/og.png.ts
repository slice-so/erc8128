import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { Resvg } from "@resvg/resvg-js"
import type { APIRoute } from "astro"
import satori from "satori"

async function loadFont(family: string, weight: number): Promise<ArrayBuffer> {
  const url = `https://fonts.googleapis.com/css2?family=${family}:wght@${weight}`
  const css = await fetch(url, {
    headers: {
      // This UA makes Google Fonts return TTF URLs
      "User-Agent":
        "Mozilla/5.0 (BB10; Touch) AppleWebKit/537.10+ (KHTML, like Gecko) Version/10.0.9.2372 Mobile Safari/537.10+"
    }
  }).then((r) => r.text())

  const match = css.match(/src: url\((.+?)\) format\('truetype'\)/)
  if (!match?.[1]) throw new Error(`Font URL not found for ${family}:${weight}`)

  return fetch(match[1]).then((r) => r.arrayBuffer())
}

function loadGlobeImage(): string | null {
  try {
    const globePath = resolve("public/globe.png")
    const data = readFileSync(globePath)
    return `data:image/png;base64,${data.toString("base64")}`
  } catch {
    return null
  }
}

export const GET: APIRoute = async () => {
  const [fontBold, fontRegular] = await Promise.all([
    loadFont("Inter", 800),
    loadFont("Inter", 400)
  ])

  const globeDataUri = loadGlobeImage()

  const markup = {
    type: "div",
    props: {
      style: {
        display: "flex",
        width: "100%",
        height: "100%",
        backgroundColor: "#050505",
        color: "white",
        fontFamily: "Inter",
        position: "relative" as const,
        overflow: "hidden" as const
      },
      children: [
        // Left content panel
        {
          type: "div",
          props: {
            style: {
              display: "flex",
              flexDirection: "column" as const,
              justifyContent: "center" as const,
              gap: "80px",
              padding: "60px 80px 80px 80px",
              width: "55%",
              zIndex: 2
            },
            children: [
              {
                type: "div",
                props: {
                  style: {
                    display: "flex",
                    flexDirection: "column" as const
                  },
                  children: [
                    // White bar
                    {
                      type: "div",
                      props: {
                        style: {
                          width: "120px",
                          height: "10px",
                          backgroundColor: "white",
                          marginBottom: "40px"
                        }
                      }
                    },
                    // ERC
                    {
                      type: "div",
                      props: {
                        style: {
                          fontSize: "100px",
                          fontWeight: 800,
                          lineHeight: 0.85,
                          letterSpacing: "-0.04em"
                        },
                        children: "ERC"
                      }
                    },
                    // 8128
                    {
                      type: "div",
                      props: {
                        style: {
                          fontSize: "100px",
                          fontWeight: 800,
                          lineHeight: 0.85,
                          letterSpacing: "-0.04em"
                        },
                        children: "8128"
                      }
                    }
                  ]
                }
              },
              // Subtitle
              {
                type: "div",
                props: {
                  style: {
                    display: "flex",
                    flexDirection: "column" as const,
                    marginTop: "48px",
                    gap: "4px"
                  },
                  children: [
                    {
                      type: "div",
                      props: {
                        style: {
                          fontSize: "46px",
                          fontWeight: 400,
                          opacity: 0.9,
                          lineHeight: 1.3
                        },
                        children: "Ethereum Identity"
                      }
                    },
                    {
                      type: "div",
                      props: {
                        style: {
                          fontSize: "46px",
                          fontWeight: 400,
                          opacity: 0.9,
                          lineHeight: 1.3
                        },
                        children: "for the Web"
                      }
                    }
                  ]
                }
              }
            ]
          }
        },
        // Right: globe image
        ...(globeDataUri
          ? [
              {
                type: "div",
                props: {
                  style: {
                    display: "flex",
                    alignItems: "center" as const,
                    justifyContent: "center" as const,
                    position: "absolute" as const,
                    right: "-40px",
                    top: "0",
                    bottom: "0",
                    width: "55%"
                  },
                  children: [
                    {
                      type: "img",
                      props: {
                        src: globeDataUri,
                        width: 600,
                        height: 600,
                        style: {
                          opacity: 0.7
                        }
                      }
                    }
                  ]
                }
              }
            ]
          : [])
      ]
    }
  }

  const svg = await satori(markup as Parameters<typeof satori>[0], {
    width: 1200,
    height: 630,
    fonts: [
      { name: "Inter", data: fontBold, weight: 800, style: "normal" as const },
      {
        name: "Inter",
        data: fontRegular,
        weight: 400,
        style: "normal" as const
      }
    ]
  })

  const resvg = new Resvg(svg, {
    fitTo: { mode: "width" as const, value: 1200 }
  })
  const png = resvg.render().asPng()

  return new Response(Buffer.from(png), {
    headers: {
      "Content-Type": "image/png",
      "Cache-Control": "public, max-age=31536000, immutable"
    }
  })
}
