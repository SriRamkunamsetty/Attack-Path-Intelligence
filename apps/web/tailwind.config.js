/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        darkBg: "#0B132B",
        cardBg: "#1C2541",
        accentBlue: "#48CAE4",
        accentOrange: "#F77F00",
        accentRed: "#D62828",
        accentGreen: "#06D6A0",
      },
    },
  },
  plugins: [],
};
