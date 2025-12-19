import React from "react";

/**
 * ModeratorPanel
 * --------------
 * UI section available to users with MODERATOR or ADMIN role.
 * Contains actions related to content moderation and user oversight.
 *
 * Access control is enforced on the BACKEND.
 * This component only controls visibility on the frontend.
 */
function ModeratorPanel() {
    return (
        <section>
            <h2>Moderator Tools</h2>

            <ul>
                <li>Something something moderator</li>
                <li>Moderator moderator</li>
            </ul>
        </section>
    );
}

export default ModeratorPanel;
