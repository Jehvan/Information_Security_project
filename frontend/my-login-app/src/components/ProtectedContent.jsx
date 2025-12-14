import React, { useState, useEffect } from "react";

function ProtectedContent() {
    const [message, setMessage] = useState("");

    useEffect(() => {
        fetch("https://localhost:8000/protected", {
            method: "GET",
            credentials: "include"
        })
            .then(res => {
                if (res.status === 401) {
                    alert("Session expired. Please login again.");
                    window.location.href = "/login";
                    return;
                }
                return res.json();
            })
            .then(data => {
                if (data) {
                    setMessage(data.message);
                }
            });
    }, []);

    return <div>{message}</div>;
}

export default ProtectedContent;
