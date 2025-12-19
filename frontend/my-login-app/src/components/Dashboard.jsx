import React from "react";
import PropTypes from "prop-types";

import ModeratorPanel from "./ModeratorPanel.jsx";
import AdminPanel from "./AdminPanel.jsx";

/**
 * Dashboard component
 * -------------------
 * Main authenticated landing page.
 * Displays different UI sections based on the user's role.
 */
function Dashboard({ user }) {
    return (
        <div>
            <h1>Dashboard</h1>

            {/* Basic user info */}
            <p>
                Welcome <b>{user.username}</b><br />
                Role: <b>{user.role}</b>
            </p>

            {/* USER content (available to all authenticated users) */}
            <section>
                <h2>User Page</h2>
                <p>This content is available to all authenticated users.</p>
            </section>

            {/* MODERATOR content (MODERATOR + ADMIN) */}
            {(user.role === "MODERATOR" || user.role === "ADMIN") && (
                <ModeratorPanel />
            )}

            {/* ADMIN-only content */}
            {user.role === "ADMIN" && (
                <AdminPanel />
            )}
        </div>
    );
}

/**
 * PropTypes validation
 * --------------------
 * Helps ESLint and future developers understand expected props.
 */
Dashboard.propTypes = {
    user: PropTypes.shape({
        username: PropTypes.string.isRequired,
        role: PropTypes.string.isRequired,
    }).isRequired,
};

export default Dashboard;
