/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          orange: "#E8651A",
          navy: "#0A2342",
        },
      },
    },
  },
  plugins: [],
};
