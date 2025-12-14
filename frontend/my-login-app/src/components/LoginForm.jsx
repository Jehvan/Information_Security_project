import React, { useState } from "react";
import "./LoginForm.css";
import PropTypes from "prop-types";

function LoginForm({ onLoginSuccess }) {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [otp, setOtp] = useState("");
    const [message, setMessage] = useState("");

    const handleSubmit = (e) => {
        e.preventDefault();

        fetch("https://localhost:8000/login", {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password, otp }),
        })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    setMessage("Welcome!");
                    if (onLoginSuccess) onLoginSuccess(data.expires_in);
                } else {
                    setMessage(data.message);
                }
            })
            .catch(() => {
                setMessage("Network Error.");
            });
    };

    return (
        <form className="login-form" onSubmit={handleSubmit}>
            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
            />
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
            />
            <input
                type="text"
                placeholder="OTP"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
            />
            <button type="submit">Log in</button>
            {message && <p>{message}</p>}
        </form>
    );
}

LoginForm.propTypes = {
    onLoginSuccess: PropTypes.func
};

export default LoginForm;
