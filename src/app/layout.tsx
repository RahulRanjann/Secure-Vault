import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Secure Vault — Private Password Manager",
  description: "A personal encrypted vault. Your passwords are encrypted in your browser.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
