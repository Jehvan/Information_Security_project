import React, { useState } from "react";
import { setUserRole } from "../services/api";

/**
 * AdminPanel
 * ----------
 * Administrative UI available ONLY to users with ADMIN role.
 *
 * Responsibilities:
 * - Assign roles to existing users
 * - Communicate with backend admin endpoint
 *
 * IMPORTANT:
 * - Real security is enforced on the backend via `require_roles("ADMIN")`
 * - This component only controls frontend visibility
 */
function AdminPanel() {
    // Username of the user whose role will be changed
    const [username, setUsername] = useState("");

    // Selected role to assign
    const [role, setRole] = useState("USER");

    // Feedback message shown to the admin
    const [message, setMessage] = useState("");

    /**
     * Sends a role change request to the backend.
     * Uses cookies for authentication (credentials: "include").
     */
    const handleSetRole = () => {
        if (!username.trim()) {
            setMessage("Please enter a username.");
            return;
        }

        setUserRole(username, role)
            .then((data) => {
                if (data.success) {
                    setMessage(data.message);
                } else {
                    setMessage(data.detail || "Failed to change role.");
                }
            })
            .catch(() => {
                setMessage("Network error.");
            });
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
                Assign roles to users.
                <br />
                <small>Only administrators can see this panel.</small>
            </p>

            {/* Username input */}
            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
            />

            {/* Role selection */}
            <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="USER">USER</option>
                <option value="MODERATOR">MODERATOR</option>
                <option value="ADMIN">ADMIN</option>
            </select>

            {/* Action button */}
            <button onClick={handleSetRole}>
                Set Role
            </button>

            {/* Feedback message */}
            {message && <p>{message}</p>}
        </section>
    );
}

export default AdminPanel;
