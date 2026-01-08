/**
 * api.js
 * ------
 * Centralized API layer for backend communication.
 * All requests go through Nginx (/api).
 * HTTPS is terminated at Nginx.
 */

const API_BASE = "/api";

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

/**
 * ADMIN: Grant temporary access to a resource
 */
export async function grantResourceAccess(username, resource, durationSeconds) {
    const res = await fetch(`${API_BASE}/admin/grant-access`, {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            username,
            resource,
            duration_seconds: durationSeconds,
        }),
    });

    return res.json();
}

/**
 * Fetch moderation reports (permission-based)
 */
export async function fetchModerationReports() {
    const res = await fetch(`${API_BASE}/moderation/reports`, {
        credentials: "include",
    });

    if (!res.ok) {
        throw new Error("Access denied");
    }

    return res.json();
}

/**
 * Fetch current user permissions
 */
export async function fetchMyPermissions() {
    const res = await fetch(`${API_BASE}/me/permissions`, {
        credentials: "include",
    });

    if (!res.ok) {
        throw new Error("Failed to fetch permissions");
    }

    return res.json();
}

/**
 * Fetch case files (temporary resource access)
 */
export async function fetchCaseFiles() {
    const res = await fetch(`${API_BASE}/case-files`, {
        credentials: "include",
    });

    if (!res.ok) {
        throw new Error("Failed to fetch case files");
    }

    return res.json();
}

/**
 * Fetch temporary admin panel data
 */
export async function fetchAdminPanelData() {
    const res = await fetch(`${API_BASE}/admin/temp-panel`, {
        credentials: "include",
    });

    if (!res.ok) {
        throw new Error("Failed to fetch admin panel data");
    }

    return res.json();
}

/**
 * ADMIN: Revoke resource access
 */
export async function revokeResourceAccess(username, resource) {
    const res = await fetch(`${API_BASE}/admin/revoke-access`, {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, resource }),
    });

    return res.json();
}
