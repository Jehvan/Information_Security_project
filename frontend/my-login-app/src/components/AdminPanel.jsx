import React, { useState } from "react";
import { setUserRole, grantResourceAccess } from "../services/api";

/**
 * AdminPanel
 * ----------
 * Administrative UI available ONLY to users with ADMIN role.
 *
 * Responsibilities:
 * 1) Assign roles to users (RBAC)
 * 2) Grant temporary access to protected resources (ReBAC)
 *
 * NOTE:
 * - Backend enforces security via require_roles("ADMIN")
 * - This component only controls frontend visibility
 */
function AdminPanel() {
    /* =======================
       ROLE MANAGEMENT (RBAC)
       ======================= */

    const [username, setUsername] = useState("");
    const [role, setRole] = useState("USER");
    const [roleMessage, setRoleMessage] = useState("");

    const handleSetRole = () => {
        if (!username.trim()) {
            setRoleMessage("Please enter a username.");
            return;
        }

        setUserRole(username, role)
            .then((data) => {
                if (data.success) {
                    setRoleMessage(data.message);
                } else {
                    setRoleMessage(data.detail || "Failed to change role.");
                }
            })
            .catch(() => {
                setRoleMessage("Network error.");
            });
    };

    /* ==============================
       RESOURCE ACCESS (ReBAC)
       ============================== */

    const [resourceUser, setResourceUser] = useState("");
    const [resource, setResource] = useState("moderation_reports");
    const [duration, setDuration] = useState(600);
    const [accessMessage, setAccessMessage] = useState("");

    const handleGrantAccess = async () => {
        if (!resourceUser.trim()) {
            setAccessMessage("Please enter a username.");
            return;
        }

        try {
            const result = await grantResourceAccess(
                resourceUser,
                resource,
                Number(duration)
            );

            if (result.success) {
                setAccessMessage(result.message);
            } else {
                setAccessMessage(result.detail || "Failed to grant access.");
            }
        } catch {
            setAccessMessage("Network error.");
        }
    };

    return (
        <section
            style={{
                border: "2px solid black",
                padding: "15px",
                marginTop: "20px",
            }}
        >
            <h2>Admin Panel</h2>

            <p>
                Administrative controls.
                <br />
                <small>Only administrators can see this panel.</small>
            </p>

            {/* =======================
               ROLE MANAGEMENT UI
               ======================= */}
            <hr />
            <h3>Role Management</h3>

            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
            />

            <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="USER">USER</option>
                <option value="MODERATOR">MODERATOR</option>
                <option value="ADMIN">ADMIN</option>
            </select>

            <button onClick={handleSetRole}>
                Set Role
            </button>

            {roleMessage && <p>{roleMessage}</p>}

            {/* ==============================
               RESOURCE ACCESS UI
               ============================== */}
            <hr />
            <h3>Temporary Resource Access</h3>

            <input
                type="text"
                placeholder="Username"
                value={resourceUser}
                onChange={(e) => setResourceUser(e.target.value)}
            />

            <select value={resource} onChange={(e) => setResource(e.target.value)}>
                <option value="moderation_reports">Moderation Reports</option>
                <option value="admin_dashboard">Admin Dashboard</option>
                <option value="case_files">Case Files</option>
            </select>

            <input
                type="number"
                min="60"
                step="60"
                placeholder="Duration (seconds)"
                value={duration}
                onChange={(e) => setDuration(e.target.value)}
            />

            <button onClick={handleGrantAccess}>
                Grant Temporary Access
            </button>

            {accessMessage && <p>{accessMessage}</p>}
        </section>
    );
}

export default AdminPanel;
