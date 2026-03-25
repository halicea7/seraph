/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        deep: '#05080d',
        card: '#090d14',
        elevated: '#0d1520',
        accent: {
          green: '#22c55e',
          amber: '#f59e0b',
          red: '#ef4444',
          blue: '#3b82f6',
          cyan: '#06b6d4',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
      boxShadow: {
        'glow-green': '0 0 12px rgba(34, 197, 94, 0.4), 0 0 30px rgba(34, 197, 94, 0.1)',
        'glow-blue':  '0 0 12px rgba(59, 130, 246, 0.4), 0 0 30px rgba(59, 130, 246, 0.1)',
        'glow-red':   '0 0 12px rgba(239, 68, 68, 0.4),  0 0 30px rgba(239, 68, 68, 0.1)',
        'glow-cyan':  '0 0 12px rgba(6, 182, 212, 0.35), 0 0 30px rgba(6, 182, 212, 0.1)',
        'card':       '0 4px 24px rgba(0,0,0,0.4)',
        'card-hover': '0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px rgba(6,182,212,0.1)',
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'cyber-grid': "radial-gradient(rgba(6, 182, 212, 0.06) 1px, transparent 1px)",
      },
      animation: {
        'glow-pulse': 'pulse-red 2s ease-in-out infinite',
        'border-glow': 'borderGlow 2.5s ease-in-out infinite',
        'fade-in-up': 'fadeInUp 0.3s ease-out',
        'shimmer': 'shimmer 1.5s infinite',
      },
    },
  },
  plugins: [],
}
