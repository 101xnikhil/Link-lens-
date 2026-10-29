/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0B0F19",
          darker: "#060911",
          card: "#111827",
          cardHover: "#182234",
          border: "#1F293D",
          borderBright: "#2E3D5B",
          cyan: "#06B6D4",
          cyanGlow: "#22D3EE",
          violet: "#8B5CF6",
          blue: "#3B82F6",
          success: "#10B981",
          warning: "#F59E0B",
          danger: "#EF4444",
          critical: "#DC2626",
          textMuted: "#94A3B8",
          textNormal: "#E2E8F0",
          textBright: "#F8FAFC"
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      },
      boxShadow: {
        'glow-cyan': '0 0 25px -5px rgba(6, 182, 212, 0.25)',
        'glow-violet': '0 0 25px -5px rgba(139, 92, 246, 0.25)',
        'glow-danger': '0 0 25px -5px rgba(239, 68, 68, 0.25)',
      }
    },
  },
  plugins: [],
}
