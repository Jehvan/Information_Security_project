import React, { useState } from "react";

function AdminPanel() {
    const [username, setUsername] = useState("");
    const [role, setRole] = useState("USER");
    const [message, setMessage] = useState("");

    const handleSetRole = () => {
        if (!username) {
            setMessage("Please enter a username.");
            return;
        }

        fetch(
            `https://localhost:8000/admin/set-role?username=${encodeURIComponent(username)}&new_role=${role}`,
            {
                method: "POST",
                credentials: "include"
            }
        )
            .then(res => res.json())
            .then(data => {
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
        <section style={{ border: "2px solid #c00", padding: "15px", marginTop: "20px" }}>
            <h2>Admin Panel</h2>

            <p>
                Assign roles to users.
                <br />
                <small>Only administrators can see this panel.</small>
            </p>

            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={e => setUsername(e.target.value)}
            />

            <select value={role} onChange={e => setRole(e.target.value)}>
                <option value="USER">USER</option>
                <option value="MODERATOR">MODERATOR</option>
                <option value="ADMIN">ADMIN</option>
            </select>

            <button onClick={handleSetRole}>
                Set Role
            </button>

            {message && <p>{message}</p>}
        </section>
    );
}

export default AdminPanel;
