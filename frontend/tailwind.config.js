/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // MITRE ATT&CK inspired colors
        'mitre': {
          'covered': '#22c55e',    // Green
          'partial': '#eab308',    // Yellow
          'uncovered': '#6b7280',  // Gray
          'critical': '#ef4444',   // Red
          'high': '#f97316',       // Orange
          'medium': '#eab308',     // Yellow
          'low': '#3b82f6',        // Blue
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
