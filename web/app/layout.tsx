import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import "./print.css";
import { MotionProvider } from "./components/MotionProvider";

// Self-hosted (00 §5.2: Google Fonts CDN is a privacy/offline-demo liability).
// Files copied one-time from the `geist` / `@fontsource/*` npm packages into
// src/fonts/ (see web/README.md-equivalent note in the task-10 report) --
// those packages are not runtime dependencies, only a source of .woff2 files.

const displayFont = localFont({
  src: [
    { path: "../src/fonts/newsreader/newsreader-latin-400-normal.woff2", weight: "400", style: "normal" },
    { path: "../src/fonts/newsreader/newsreader-latin-400-italic.woff2", weight: "400", style: "italic" },
    { path: "../src/fonts/newsreader/newsreader-latin-600-normal.woff2", weight: "600", style: "normal" },
    { path: "../src/fonts/newsreader/newsreader-latin-700-normal.woff2", weight: "700", style: "normal" },
  ],
  variable: "--font-newsreader",
  display: "swap",
});

const uiFont = localFont({
  src: "../src/fonts/geist-sans/Geist-Variable.woff2",
  weight: "100 900",
  variable: "--font-geist-sans",
  display: "swap",
});

const monoFont = localFont({
  src: [
    { path: "../src/fonts/ibm-plex-mono/ibm-plex-mono-latin-400-normal.woff2", weight: "400", style: "normal" },
    { path: "../src/fonts/ibm-plex-mono/ibm-plex-mono-latin-600-normal.woff2", weight: "600", style: "normal" },
  ],
  variable: "--font-ibm-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Agent Perimeter",
  description: "Security posture scanner for MCP servers and tool-using agents.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" data-density="compact">
      <body
        className={`${displayFont.variable} ${uiFont.variable} ${monoFont.variable} antialiased`}
      >
        <MotionProvider>{children}</MotionProvider>
      </body>
    </html>
  );
}
