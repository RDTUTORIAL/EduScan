/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: ['./src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          PRIMARY: '#0f172a',
          accent: '#06b6d4',
          panel: '#0b1120',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
        mono: ['"JetBrains Mono"', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 25px rgba(6, 182, 212, 0.35)',
      },
    },
  },
  plugins: [],
};