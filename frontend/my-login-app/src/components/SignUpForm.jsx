import React, {useState} from "react";
import "./SignUpForm.css";
import QRCode from "react-qr-code";

function SignUpForm() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [message, setMessage] = useState("");
    const [email, setEmail] = useState("");
    const [otpStep, setOtpStep] = useState("");
    const [otpUri, setOtpUri] = useState("");
    const [totpSecret, setTotpSecret] = useState("");
    const [otp,setOtp] = useState("");

    const handleFirstSubmit = (e) => {
        e.preventDefault()
        if (!username || !password || !confirmPassword || !email) {
            setMessage("All fields are required");
            return;
        }
        if (password !== confirmPassword) {
            setMessage("Passwords don't match");
            return;
        }

        fetch ("https://localhost:8000/signup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password }),
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.otp_required) {
                    setOtpStep(true);
                    setOtpUri(data.otp_uri);
                    setTotpSecret(data.totp_secret);
                    setMessage("Scan the QR code and enter the OTP from your authenticator app.");
                } else {
                    setMessage(data.message || "Signup failed.");
                }
            })
            .catch(() => {
                setMessage("Network Error.")
            })
    }

    const handleOtpSubmit = (e) => {
        e.preventDefault();
        console.log("Finish signup clicked", { username, email, password, otp, totpSecret })
        fetch ("https://localhost:8000/signup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password, otp, totp_secret: totpSecret }),
        })
            .then((res) => res.json())
            .then((data) => {
                setMessage(data.message || (data.success ? "Signed up successfully" : "Signup failed."));
                if (data.success) {
                    setOtpStep(false)
                    setUsername("")
                    setPassword("")
                    setConfirmPassword("")
                    setEmail("")
                    setOtpUri("")
                    setTotpSecret("")
                    setOtp();
                }
            })
            .catch(() => {
                setMessage("Network Error.")
            })
    }


    return (
        <form className="signup-form" onSubmit={otpStep ? handleOtpSubmit : handleFirstSubmit}>
            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled = {otpStep}
            />
            <input
                type="text"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled = {otpStep}
            />
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled = {otpStep}
            />
            <input
                type="password"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                disabled = {otpStep}
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
                        onChange={e => setOtp(e.target.value)}
                        />
                </>
            )}
            <button type="submit">{otpStep ? "Finish Signup" : "Sign up"}</button>
            {message && <p>{message}</p>}
        </form>
    );
}

export default SignUpForm;