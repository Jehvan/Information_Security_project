/**
 * api.js
 * ------
 * Centralized API layer for backend communication.
 * All fetch() calls live here.
 * Components only import and use functions.
 */

const API_BASE = "https://localhost:8000";

/**
 * Login user (OTP + credentials)
 */
export async function login({ username, password, otp }) {
    const res = await fetch(`${API_BASE}/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, otp }),
    });

    return res.json();
}

/**
 * Logout current user
 */
export async function logout() {
    await fetch(`${API_BASE}/logout`, {
        method: "POST",
        credentials: "include",
    });
}

/**
 * Check if session is valid
 */
export async function checkSession() {
    const res = await fetch(`${API_BASE}/protected`, {
        credentials: "include",
    });

    return res.ok;
}

/**
 * Get current authenticated user
 */
export async function getCurrentUser() {
    const res = await fetch(`${API_BASE}/me`, {
        credentials: "include",
    });

    if (!res.ok) {
        throw new Error("Not authenticated");
    }

    return res.json();
}

/**
 * ADMIN: Set user role
 */
export async function setUserRole(username, newRole) {
    const res = await fetch(
        `${API_BASE}/admin/set-role?username=${encodeURIComponent(
            username
        )}&new_role=${newRole}`,
        {
            method: "POST",
            credentials: "include",
        }
    );

    return res.json();
}
