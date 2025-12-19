/**
 * App.jsx
 * -------
 * Root React component.
 *
 * Responsibilities:
 * - Manage authentication state
 * - Fetch current user session
 * - Handle login/logout
 * - Render the correct UI based on authentication status
 */

import React, { useEffect, useState } from "react";
import "./App.css";

import LoginForm from "./components/LoginForm";
import SignUpForm from "./components/SignUpForm";
import Dashboard from "./components/Dashboard";

import {
    checkSession,
    getCurrentUser,
    logout as apiLogout,
} from "./services/api";


function App() {
    // ---------------------------------------------
    // Global application state
    // ---------------------------------------------

    // Toggle between Login and Signup views
    const [showSignUp, setShowSignUp] = useState(false);

    // Whether the user is authenticated
    const [isAuthenticated, setIsAuthenticated] = useState(false);

    // Timer used for automatic logout when JWT expires
    const [logoutTimer, setLogoutTimer] = useState(null);

    // Current authenticated user (username + role)
    const [user, setUser] = useState(null);

    // ---------------------------------------------
    // Initial authentication check (on page load)
    // ---------------------------------------------
    // Calls a protected endpoint to see if the
    // session cookie is valid.
    useEffect(() => {
        checkSession()
            .then((valid) => setIsAuthenticated(valid))
            .catch(() => setIsAuthenticated(false));
    }, []);


    // ---------------------------------------------
    // Load current user details when authenticated
    // ---------------------------------------------
    useEffect(() => {
        if (!isAuthenticated) {
            setUser(null);
            return;
        }

        getCurrentUser()
            .then((data) => setUser(data))
            .catch(() => setUser(null));
    }, [isAuthenticated]);


    // ---------------------------------------------
    // Handle successful login
    // ---------------------------------------------
    // Starts an automatic logout timer based on
    // the token expiration time returned by backend.
    const handleLoginSuccess = (expiresIn = 60) => {
        setIsAuthenticated(true);

        if (logoutTimer) {
            clearTimeout(logoutTimer);
        }

        const timer = setTimeout(() => {
            alert("Session expired");
            setIsAuthenticated(false);
        }, expiresIn * 1000);

        setLogoutTimer(timer);
    };

    // ---------------------------------------------
    // Handle logout
    // ---------------------------------------------
    // Deletes the session cookie server-side
    // and clears frontend state.
    const handleLogout = () => {
        apiLogout().finally(() => {
            if (logoutTimer) clearTimeout(logoutTimer);
            setIsAuthenticated(false);
        });
    };


    // ---------------------------------------------
    // Render UI
    // ---------------------------------------------
    return (
        <div>
            {!isAuthenticated ? (
                <>
                    <h1>{showSignUp ? "Sign Up" : "Login"}</h1>

                    {showSignUp ? (
                        <SignUpForm />
                    ) : (
                        <LoginForm onLoginSuccess={handleLoginSuccess} />
                    )}

                    <p>
                        {showSignUp ? (
                            <>
                                Already have an account?{" "}
                                <button onClick={() => setShowSignUp(false)}>
                                    Log In
                                </button>
                            </>
                        ) : (
                            <>
                                Don&apos;t have an account?{" "}
                                <button onClick={() => setShowSignUp(true)}>
                                    Sign Up
                                </button>
                            </>
                        )}
                    </p>
                </>
            ) : (
                <>
                    {user && <Dashboard user={user} />}
                    <button onClick={handleLogout}>Log Out</button>
                </>
            )}
        </div>
    );
}

export default App;
