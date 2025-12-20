import React, { useEffect, useState } from "react";
import PropTypes from "prop-types";

import ModeratorPanel from "./ModeratorPanel.jsx";
import AdminPanel from "./AdminPanel.jsx";

import {
    fetchModerationReports,
    fetchMyPermissions,
    fetchCaseFiles,
    fetchAdminPanelData,
} from "../services/api";

/**
 * Format remaining time until expiration
 */
function formatRemainingTime(expiresAt) {
    const remainingMs = new Date(expiresAt).getTime() - Date.now();

    if (remainingMs <= 0) return "Expired";

    const seconds = Math.floor(remainingMs / 1000);
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;

    return `${minutes}m ${secs}s`;
}

function Dashboard({ user }) {
    const [permissions, setPermissions] = useState([]);
    const [reports, setReports] = useState(null);
    const [caseFiles, setCaseFiles] = useState(null);
    const [adminData, setAdminData] = useState(null);
    const [error, setError] = useState("");
    const hasPermission = (resource) =>
        permissions.some((p) => p.resource === resource);


    /**
     * Load + clean permissions:
     * - remove expired
     * - dedupe by resource (keep latest expiry)
     */
    useEffect(() => {
        let alive = true;

        const loadPermissions = async () => {
            try {
                const data = await fetchMyPermissions();
                const now = Date.now();

                const map = new Map();

                for (const p of data.permissions || []) {
                    const exp = new Date(p.expires_at).getTime();
                    if (Number.isNaN(exp)) continue;
                    if (exp <= now) continue; // drop expired

                    const existing = map.get(p.resource);
                    if (!existing || new Date(existing.expires_at).getTime() < exp) {
                        map.set(p.resource, p);
                    }
                }

                if (alive) {
                    setPermissions(Array.from(map.values()));
                }
            } catch {
                if (alive) setPermissions([]);
            }
        };

        loadPermissions();
        const interval = setInterval(loadPermissions, 2000);

        return () => {
            alive = false;
            clearInterval(interval);
        };
    }, []);

    /**
     * Resource config (single source of truth)
     */
    const resourceConfig = {
        moderation_reports: {
            label: "View Moderation Reports",
            handler: async () => {
                const data = await fetchModerationReports();
                setReports(data.data);
                setError("");
            },
        },
        case_files: {
            label: "View Case Files",
            handler: async () => {
                const data = await fetchCaseFiles();
                setCaseFiles(data.data);
                setError("");
            },
        },
        admin_dashboard: {
            label: "Open Temporary Admin Panel",
            handler: async () => {
                const data = await fetchAdminPanelData();
                setAdminData(data.data);
                setError("");
            },
        },
    };

    return (
        <div>
            <h1>Dashboard</h1>

            <p>
                Welcome <b>{user.username}</b>
                <br />
                Role: <b>{user.role}</b>
            </p>

            {/* Base user content */}
            <section>
                <h2>User Page</h2>
                <p>This content is available to all authenticated users.</p>

                {/* Permission-based buttons */}
                {permissions.map((perm) => {
                    const config = resourceConfig[perm.resource];
                    if (!config) return null;

                    return (
                        <div key={perm.resource} style={{ marginBottom: "10px" }}>
                            <button
                                onClick={async () => {
                                    try {
                                        await config.handler();
                                    } catch {
                                        setError("Access failed.");
                                    }
                                }}
                            >
                                {config.label}
                            </button>

                            <small style={{ marginLeft: "10px" }}>
                                ⏳ {formatRemainingTime(perm.expires_at)}
                            </small>
                        </div>
                    );
                })}

                {error && <p style={{ color: "red" }}>{error}</p>}
            </section>

            {/* Render protected data */}
            {reports && (
                <section>
                    <h3>Moderation Reports</h3>
                    <ul>
                        {reports.map((r, i) => (
                            <li key={i}>{r}</li>
                        ))}
                    </ul>
                </section>
            )}

            {caseFiles && (
                <section>
                    <h3>Case Files</h3>
                    <ul>
                        {caseFiles.map((c, i) => (
                            <li key={i}>{c}</li>
                        ))}
                    </ul>
                </section>
            )}

            {adminData && (
                <section style={{ border: "2px dashed red", padding: "10px" }}>
                    <h3>Temporary Admin Panel</h3>
                    <ul>
                        <li>System status: {adminData.system_status}</li>
                        <li>Active users: {adminData.active_users}</li>
                        <li>Alerts: {adminData.alerts}</li>
                    </ul>

                </section>
            )}

            {/* Permanent role-based panels */}
            {(user.role === "MODERATOR" || user.role === "ADMIN") && (
                <ModeratorPanel />
            )}

            {(user.role === "ADMIN" || hasPermission("admin_panel")) && (
                <AdminPanel />
            )}

        </div>
    );
}

Dashboard.propTypes = {
    user: PropTypes.shape({
        username: PropTypes.string.isRequired,
        role: PropTypes.string.isRequired,
    }).isRequired,
};

export default Dashboard;
