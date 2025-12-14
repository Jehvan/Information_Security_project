import React, { useEffect, useState } from 'react';
import './App.css'
import LoginForm from "./components/LoginForm"
import SignUpForm from "./components/SignupForm"
import ProtectedContent from "./components/ProtectedContent"
import log from "eslint-plugin-react/lib/util/log.js";

function App() {
    const [showSignUp, setShowSignUp] = useState(false);
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [logoutTimer, setLogoutTimer] = useState(null);

    useEffect(() => {
        fetch("https://localhost:8000/protected", {
            credentials: "include"
        })
            .then(res => {
                if (res.status === 200) {
                    setIsAuthenticated(true);
                } else {
                    setIsAuthenticated(false);
                }
            })
            .catch(() => setIsAuthenticated(false));
    }, []);

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


    const handleLogout = () => {
        fetch("https://localhost:8000/logout", {
            method: "POST",
            credentials: "include"
        }).finally(() => {
            if(logoutTimer) clearTimeout(logoutTimer);
            setIsAuthenticated(false);
        });
    };

    return (
        <div>
            {!isAuthenticated ? (
                <>
                    <h1>{showSignUp ? "Sign Up" : "Login"}</h1>
                    {showSignUp ? (
                        <SignUpForm/>
                    ) : (
                        <LoginForm onLoginSuccess={handleLoginSuccess}/>
                    )}
                    <p>
                        {showSignUp ? (
                            <>
                                Already have an account?{" "}
                                <button onClick={() => setShowSignUp(false)}>Log In</button>
                            </>
                        ) : (
                            <>
                                Don&#39;t have an account?{" "}
                                <button onClick={() => setShowSignUp(true)}>Sign Up</button>
                            </>
                        )}
                    </p>
                </>
            ) : (
                <>
                    <ProtectedContent/>
                    <button onClick={handleLogout}>Log Out</button>
                </>
            )}
        </div>
    );
}

export default App;
