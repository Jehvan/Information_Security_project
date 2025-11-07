import React, {useState} from "react";

function ProtectedContent() {
    const [message,setMessage] = useState('');

    React.useEffect(() => {
        fetch("https://localhost:8000/protected",
            {
                headers: {
                    "Authorization": "Bearer " + localStorage.getItem("token"),
                }
            })
            .then(res => {
                if (res.status === 401) {
                    alert("Session expired. Please login again.")
                    localStorage.removeItem("token");
                    window.location.reload();
                }
                return res.json();
            })
            .then(data => {
                setMessage(data.message);
            })
    }, [])
    return <div>{message}</div>;
}

export default ProtectedContent;