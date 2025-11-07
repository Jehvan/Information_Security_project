import React, {useEffect, useState} from 'react';
import './App.css'
import LoginForm from "./components/LoginForm"
import SignUpForm from "./components/SignupForm"
import ProtectedContent from "./components/ProtectedContent"

function App() {
    const [showSignUp, setShowSignUp] = useState(false);
    const [isAuthenticated, setIsAuthenticated] = useState(false);

    useEffect(() => {
        setIsAuthenticated(!!localStorage.getItem("token"));
    }, [])

    const handleLoginSuccess = () => {
        setIsAuthenticated(true);
    }

    const handleLogout = () => {
        localStorage.removeItem("token");
        setIsAuthenticated(false)
    }

    return (
        <div>
            {!isAuthenticated ? (
                <>
                    <h1>{showSignUp ? "Sign Up" : "Login"}</h1>
                    {showSignUp ? (
                        <SignUpForm/>
                    ) : (
                        <LoginForm onLoginSuccess={handleLoginSuccess} />
                    )}
                    <p>
                        {showSignUp ? (
                            <>
                                Already have an account?{" "}
                                <button onClick={() => setShowSignUp(false)}>Log In</button>
                            </>
                        ) : (
                            <>
                                Don't have an account?{" "}
                                <button onClick={() => setShowSignUp(true)}>Sign Up</button>
                            </>
                        )}
                    </p>
                </>
            ) : (
                <>

                    <ProtectedContent/>
                    <button onClick={handleLogout}>
                        Log Out
                    </button>
                </>
            )}
        </div>
    );
}

export default App
