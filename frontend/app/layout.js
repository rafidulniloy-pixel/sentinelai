import "./globals.css";
import CircuitBackground from "./CircuitBackground";

export const metadata = {
  title: "SentinelAI",
  description: "AI-Powered Security Operations Assistant",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        {/* The circuit background renders behind EVERY page. */}
        <CircuitBackground />
        {children}
      </body>
    </html>
  );
}