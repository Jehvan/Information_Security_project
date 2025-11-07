import React, {useState} from "react";
import "./SignUpForm.css";

function SignUpForm() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [message, setMessage] = useState("");
    const [email, setEmail] = useState("");


    const handleSubmit = (e) => {
        e.preventDefault()
        if (!username || !password || !confirmPassword || !email) {
            setMessage("All fields are required.");
            return;
        }
        if (password !== confirmPassword) {
            setMessage("Passwords don't match");
            return;
        }

        fetch ("https://localhost:8000/signup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username,email,password }),
        })
            .then((res) => res.json())
            .then((data) => {
                setMessage(data.message || (data.success ? "Signed up successfully!" : "Signup failed."));

            })
            .catch(() => {
                setMessage("Network Error.")
            });
    };

    return (
        <form className="signup-form" onSubmit={handleSubmit}>
            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
            />
            <input
                type="text"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
            />
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
            />
            <input
                type="password"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
            />
            <button type="submit">Sign up</button>
            {message && <p>{message}</p>}
        </form>
    );
}

export default SignUpForm;