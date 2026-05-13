import type { Config } from 'tailwindcss';

export default {
  darkMode: ['class'],
  content: ['./pages/**/*.{ts,tsx}','./components/**/*.{ts,tsx}','./app/**/*.{ts,tsx}','./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Space Grotesk', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      colors: {
        bg:        '#030308',
        'bg-2':    '#08080f',
        'bg-3':    '#0d0d1e',
        purple:    { DEFAULT: '#8b5cf6', dim: '#6d28d9', deep: '#4c1d95', light: '#a78bfa', faint: '#8b5cf610' },
        border:    { DEFAULT: 'rgba(255,255,255,0.07)', glow: 'rgba(139,92,246,0.25)' },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'glow-purple':     'radial-gradient(ellipse at 50% 0%, rgba(139,92,246,0.25) 0%, transparent 70%)',
        'glow-left':       'radial-gradient(ellipse at 0% 50%, rgba(139,92,246,0.15) 0%, transparent 60%)',
        'glow-right':      'radial-gradient(ellipse at 100% 30%, rgba(59,130,246,0.08) 0%, transparent 60%)',
      },
      keyframes: {
        'fade-up':  { from: { opacity:'0', transform:'translateY(16px)' }, to: { opacity:'1', transform:'translateY(0)' } },
        'fade-in':  { from: { opacity:'0' }, to: { opacity:'1' } },
        float:      { '0%,100%': { transform:'translateY(0)' }, '50%': { transform:'translateY(-8px)' } },
        shimmer:    { '0%': { backgroundPosition:'200% 0' }, '100%': { backgroundPosition:'-200% 0' } },
        'dot-ping': { '0%,100%': { boxShadow:'0 0 0 0 rgba(139,92,246,0.6)' }, '50%': { boxShadow:'0 0 0 5px rgba(139,92,246,0)' } },
        scanline:   { '0%': { top:'-150px' }, '100%': { top:'100vh' } },
        'spin-slow':{ from:{ transform:'rotate(0deg)' }, to:{ transform:'rotate(360deg)' } },
      },
      animation: {
        'fade-up':   'fade-up 0.5s ease-out both',
        'fade-in':   'fade-in 0.4s ease-out both',
        float:       'float 4s ease-in-out infinite',
        shimmer:     'shimmer 1.6s ease-in-out infinite',
        'dot-ping':  'dot-ping 2s ease-in-out infinite',
        scanline:    'scanline 8s linear infinite',
        'spin-slow': 'spin-slow 12s linear infinite',
      },
      borderRadius: { lg: '12px', xl: '16px', '2xl': '20px', '3xl': '28px' },
      backdropBlur: { xs: '4px' },
      boxShadow: {
        'glow-sm':  '0 0 20px rgba(139,92,246,0.2)',
        'glow-md':  '0 0 40px rgba(139,92,246,0.3)',
        'glow-lg':  '0 0 80px rgba(139,92,246,0.4)',
        'card':     '0 4px 24px rgba(0,0,0,0.4)',
        'card-hover':'0 8px 40px rgba(0,0,0,0.5), 0 0 1px rgba(139,92,246,0.3)',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
} satisfies Config;
