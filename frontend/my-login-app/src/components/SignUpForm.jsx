/**
 * SignUpForm.jsx
 * --------------
 * User registration form with TOTP (OTP) enrollment.
 *
 * Registration flow:
 * 1. User submits username, email, and password
 * 2. Backend generates a TOTP secret and QR code
 * 3. User scans QR code with authenticator app
 * 4. User submits OTP to complete registration
 */

import React, { useState } from "react";
import QRCode from "react-qr-code";
import "./SignUpForm.css";

function SignUpForm() {
    // ---------------------------------------------
    // Form state (initial registration data)
    // ---------------------------------------------

    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    // ---------------------------------------------
    // OTP enrollment state
    // ---------------------------------------------

    // Whether the form is in OTP verification step
    const [otpStep, setOtpStep] = useState(false);

    // URI used to generate QR code for authenticator apps
    const [otpUri, setOtpUri] = useState("");

    // TOTP secret returned by backend (used only to finish signup)
    const [totpSecret, setTotpSecret] = useState("");

    // OTP entered by the user
    const [otp, setOtp] = useState("");

    // ---------------------------------------------
    // UI feedback
    // ---------------------------------------------

    const [message, setMessage] = useState("");

    // ---------------------------------------------
    // Step 1: Submit basic registration data
    // ---------------------------------------------
    const handleInitialSubmit = (event) => {
        event.preventDefault();

        // Basic client-side validation
        if (!username || !email || !password || !confirmPassword) {
            setMessage("All fields are required");
            return;
        }

        if (password !== confirmPassword) {
            setMessage("Passwords do not match");
            return;
        }

        // Send initial signup request
        fetch("https://localhost:8000/signup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password }),
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.otp_required) {
                    // Backend requests OTP enrollment
                    setOtpStep(true);
                    setOtpUri(data.otp_uri);
                    setTotpSecret(data.totp_secret);
                    setMessage(
                        "Scan the QR code and enter the OTP from your authenticator app."
                    );
                } else {
                    setMessage(data.message || "Signup failed.");
                }
            })
            .catch(() => {
                setMessage("Network error. Please try again.");
            });
    };

    // ---------------------------------------------
    // Step 2: Submit OTP to complete registration
    // ---------------------------------------------
    const handleOtpSubmit = (event) => {
        event.preventDefault();

        fetch("https://localhost:8000/signup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username,
                email,
                password,
                otp,
                totp_secret: totpSecret,
            }),
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.success) {
                    setMessage("Signed up successfully");

                    // Reset form state
                    setOtpStep(false);
                    setUsername("");
                    setEmail("");
                    setPassword("");
                    setConfirmPassword("");
                    setOtp("");
                    setOtpUri("");
                    setTotpSecret("");
                } else {
                    setMessage(data.message || "Signup failed.");
                }
            })
            .catch(() => {
                setMessage("Network error. Please try again.");
            });
    };

    // ---------------------------------------------
    // Render form
    // ---------------------------------------------
    return (
        <form
            className="signup-form"
            onSubmit={otpStep ? handleOtpSubmit : handleInitialSubmit}
        >
            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={otpStep}
                required
            />

            <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={otpStep}
                required
            />

            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={otpStep}
                required
            />

            <input
                type="password"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={otpStep}
                required
            />

            {otpStep && (
                <>
                    <div>
                        <p>Scan this QR code with your authenticator app:</p>
                        <QRCode value={otpUri} />
                    </div>

                    <input
                        type="text"
                        placeholder="Enter OTP from app"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)}
                        required
                    />
                </>
            )}

            <button type="submit">
                {otpStep ? "Finish Signup" : "Sign up"}
            </button>

            {message && <p>{message}</p>}
        </form>
    );
}

export default SignUpForm;
