/** @type {import('tailwindcss').Config} */
// Design tokens. One accent (brand orange) over black/white neutrals; dark
// zones use the *-dark tokens, light zones the plain ink/dim/line tokens.
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        dark: "#121316",
        "dark-surface": "#191B1F",
        "dark-line": "#2A2D33",
        "on-dark": "#ECEDEF",
        "dim-dark": "#9198A3",
        light: "#FFFFFF",
        "light-alt": "#F5F5F3",
        "light-line": "#E2E1DC",
        ink: "#14151A",
        dim: "#63666E",
        brand: "#E85D2C",
        "brand-dim": "#B84A22",
      },
      fontFamily: {
        display: ['"Archivo"', "system-ui", "sans-serif"],
        sans: ['"Public Sans"', "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
    // Replaced, not extended: soft large corners and drop shadows are not
    // part of this system, so the utilities simply don't exist.
    borderRadius: {
      none: "0",
      sm: "2px",
      DEFAULT: "3px",
      md: "4px",
    },
    boxShadow: {
      none: "none",
    },
  },
  plugins: [],
};
