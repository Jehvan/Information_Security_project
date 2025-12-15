import React, { useEffect, useState } from 'react';
import './App.css'
import LoginForm from "./components/LoginForm"
import SignUpForm from "./components/SignupForm"
import Dashboard from "./components/Dashboard";



function App() {
    const [showSignUp, setShowSignUp] = useState(false);
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [logoutTimer, setLogoutTimer] = useState(null);
    const [user, setUser] = useState(null);

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

    useEffect(() => {
        if (!isAuthenticated) {
            setUser(null);
            return;
        }

        fetch("https://localhost:8000/me", {
            credentials: "include"
        })
            .then(res => res.json())
            .then(data => setUser(data))
            .catch(() => setUser(null));
    }, [isAuthenticated]);


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
                    {user && <Dashboard user={user} />}
                    <button onClick={handleLogout}>Log Out</button>
                </>
            )}
        </div>
    );
}

export default App;
