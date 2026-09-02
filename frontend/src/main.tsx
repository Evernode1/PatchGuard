import React from "react";
import ReactDOM from "react-dom/client";
import { PrivyProvider } from "@privy-io/react-auth";
import App from "./App";
import "./index.css";

const PRIVY_APP_ID = import.meta.env.VITE_PRIVY_APP_ID ?? "";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <PrivyProvider
      appId={PRIVY_APP_ID}
      config={{
        embeddedWallets: { createOnLogin: "users-without-wallets" },
        appearance: { theme: "dark", accentColor: "#3ddc97" },
      }}
    >
      <App />
    </PrivyProvider>
  </React.StrictMode>,
);
