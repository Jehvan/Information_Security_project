import React, {useState} from "react";
import "./LoginForm.css";

function LoginForm( {onLoginSuccess} ) {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState("");
    const [otp, setOtp] = useState("");

    const handleSubmit = (e) => {
        e.preventDefault()
        fetch ("https://localhost:8000/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username,password,otp }),
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.success) {
                    localStorage.setItem("token", data.token);
                    setMessage("Welcome!");
                    if (onLoginSuccess) onLoginSuccess();
                } else {
                    setMessage(data.message);
                }
            })
            .catch(() => {
                setMessage("Network Error.")
            });
    };

    return (
        <form className="login-form" onSubmit={handleSubmit} >
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
export default LoginForm;