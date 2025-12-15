import React from "react";
import ModeratorPanel from "./ModeratorPanel.jsx";
import AdminPanel from "./AdminPanel";

function Dashboard({ user }) {
    return (
        <div>
            <h1>Dashboard</h1>

            <p>
                Welcome <b>{user.username}</b><br />
                Role: <b>{user.role}</b>
            </p>

            {/* USER content */}
            <section>
                <h2>User Page</h2>
                <p>This content is available to all authenticated users.</p>
            </section>

            {/* MODERATOR upgrade */}
            {(user.role === "MODERATOR" || user.role === "ADMIN") && (
                <ModeratorPanel />
            )}

            {/* ADMIN upgrade */}
            {user.role === "ADMIN" && (
                <AdminPanel />
            )}
        </div>
    );
}

export default Dashboard;
