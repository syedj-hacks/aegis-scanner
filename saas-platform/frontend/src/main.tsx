import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";

import App from "./App";
import "./index.css";
import { AuthProvider } from "./lib/auth";

// HashRouter (not BrowserRouter) so the app works as a GitHub Pages project
// site under /aegis-saas/ with no server-side rewrite: routes live after the
// # and a page refresh never 404s.
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HashRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </HashRouter>
  </React.StrictMode>
);
