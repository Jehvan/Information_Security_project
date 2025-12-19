/**
 * main.jsx
 * --------
 * Application entry point.
 *
 * This file mounts the React application
 * into the root DOM element.
 *
 * React.StrictMode is intentionally NOT used
 * to avoid double execution of effects during development,
 * which can interfere with authentication flows.
 */

import React from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import "./index.css";

// Get the root DOM node
const container = document.getElementById("root");

// Create React root (React 18+)
const root = createRoot(container);

// Render the application
root.render(<App />);
