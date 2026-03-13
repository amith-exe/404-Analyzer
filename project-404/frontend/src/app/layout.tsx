import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Outside-In Cloud Visibility Scanner",
  description: "Subdomain enumeration, crawling, and vulnerability scanning dashboard",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased bg-gray-950 text-gray-100 min-h-screen">
        <nav className="border-b border-gray-800 px-6 py-3 flex items-center gap-3">
          <span className="text-blue-400 font-bold text-lg">🔭 Outside-In Scanner</span>
          <a href="/" className="text-gray-400 hover:text-white text-sm ml-4">New Scan</a>
        </nav>
        <main className="max-w-7xl mx-auto px-4 py-8">{children}</main>
      </body>
    </html>
  );
}
