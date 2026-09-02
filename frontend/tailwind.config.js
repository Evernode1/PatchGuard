/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#0b0f0e",       // near-black terminal background
        panel: "#111715",      // card background
        line: "#233029",       // hairline borders
        ink: "#e6f2ec",        // primary text
        dim: "#8fa79a",        // secondary text
        clear: "#3ddc97",      // clear / healthy signal (terminal green)
        watch: "#f5c445",      // watch / warning signal (amber)
        breach: "#ff5d5d",     // breach / critical signal (red)
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        glow: "0 0 0 1px #233029, 0 8px 24px -8px rgba(61,220,151,0.15)",
      },
    },
  },
  plugins: [],
};
