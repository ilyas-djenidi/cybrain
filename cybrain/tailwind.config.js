/** @type {import('tailwindcss').Config} */
export default {
    darkMode: 'class',
    content: [
        './index.html',
        './src/**/*.{js,jsx,ts,tsx}',
    ],
    theme: {
        extend: {
            fontFamily: {
                orbitron: ['Orbitron', 'sans-serif'],
                inter: ['Inter', 'sans-serif'],
            },
            colors: {
                cyber: {
                    dark:   '#000000',
                    panel:  '#0a0b0f',
                    cyan:   '#00f5d4',
                    purple: '#a855f7',
                }
            },
            backgroundSize: {
                'dot-sm': '32px 32px',
                'dot-md': '48px 48px',
            }
        }
    },
    plugins: [],
}
