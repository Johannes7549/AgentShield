import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0b0d10",
        panel: "#12151a",
        line: "#2a3038",
        muted: "#8b95a5",
        accent: "#8fb9b0",
      },
      fontFamily: {
        sans: ['"Segoe UI"', '"Helvetica Neue"', "Arial", "sans-serif"],
        mono: ['"Cascadia Mono"', "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
