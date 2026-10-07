from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, Response
from pathlib import Path
import secrets
import time
import json

app = FastAPI()

STORAGE = Path("storage")
STORAGE.mkdir(exist_ok=True)

META = STORAGE / "metadata.json"

if META.exists():
    metadata = json.loads(META.read_text())
else:
    metadata = {}


def save_metadata():
    META.write_text(json.dumps(metadata))


def cleanup():
    now = int(time.time())

    expired = []

    for token, info in metadata.items():
        if info["expires"] <= now:
            expired.append(token)

    for token in expired:
        path = STORAGE / f"{token}.bin"

        if path.exists():
            path.unlink()

        del metadata[token]

    if expired:
        save_metadata()


@app.get("/", response_class=HTMLResponse)
async def home():
    return """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>DeadDrop</title>
<style>
body {
    font-family: sans-serif;
    max-width: 700px;
    margin: 60px auto;
    padding: 20px;
}
input, button {
    padding: 12px;
    font-size: 16px;
}
button {
    cursor: pointer;
}
#result {
    margin-top: 20px;
    word-break: break-all;
}
</style>
</head>
<body>

<h1>DeadDrop</h1>
<p>Encrypted file drop.</p>

<input id="file" type="file">
<button onclick="upload()">Encrypt and Upload</button>

<div id="result"></div>

<script>
function base64url(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary)
        .replace(/\\+/g, "-")
        .replace(/\\//g, "_")
        .replace(/=/g, "");
}

function fromBase64url(value) {
    value = value
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    while (value.length % 4) {
        value += "=";
    }

    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

async function upload() {
    const fileInput = document.getElementById("file");
    const result = document.getElementById("result");

    if (!fileInput.files.length) {
        result.innerText = "Choose a file first.";
        return;
    }

    const file = fileInput.files[0];

    const key = await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );

    const rawKey = new Uint8Array(
        await crypto.subtle.exportKey("raw", key)
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const plaintext = await file.arrayBuffer();

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        plaintext
    );

    const encrypted = new Uint8Array(
        iv.length + ciphertext.byteLength
    );

    encrypted.set(iv, 0);
    encrypted.set(new Uint8Array(ciphertext), iv.length);

    const form = new FormData();

    form.append(
        "file",
        new Blob([encrypted], {
            type: "application/octet-stream"
        }),
        "encrypted.bin"
    );

    form.append("name", file.name);

    const response = await fetch("/upload", {
        method: "POST",
        body: form
    });

    if (!response.ok) {
        result.innerText = "Upload failed.";
        return;
    }

    const data = await response.json();

    const keyString = base64url(rawKey);

    const link =
        window.location.origin +
        "/download/" +
        data.token +
        "#key=" +
        keyString;

    result.innerHTML =
        "<p>Upload complete.</p>" +
        "<input style='width:100%' value='" +
        link +
        "' readonly onclick='this.select()'>";

    await navigator.clipboard.writeText(link);
}

async function downloadFile() {
    const result = document.getElementById("result");

    const path = window.location.pathname;
    const token = path.split("/").pop();

    const params = new URLSearchParams(
        window.location.hash.substring(1)
    );

    const keyString = params.get("key");

    if (!keyString) {
        result.innerText = "Missing decryption key.";
        return;
    }

    const response = await fetch(
        "/blob/" + encodeURIComponent(token)
    );

    if (!response.ok) {
        result.innerText = "File unavailable.";
        return;
    }

    const encrypted = new Uint8Array(
        await response.arrayBuffer()
    );

    const iv = encrypted.slice(0, 12);
    const ciphertext = encrypted.slice(12);

    const key = await crypto.subtle.importKey(
        "raw",
        fromBase64url(keyString),
        {
            name: "AES-GCM"
        },
        false,
        ["decrypt"]
    );

    try {
        const plaintext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            ciphertext
        );

        const responseInfo = await fetch(
            "/info/" + encodeURIComponent(token)
        );

        const info = await responseInfo.json();

        const blob = new Blob([plaintext]);

        const link = document.createElement("a");

        link.href = URL.createObjectURL(blob);
        link.download = info.name;

        document.body.appendChild(link);
        link.click();
        link.remove();

        result.innerText = "File decrypted.";
    } catch {
        result.innerText = "Decryption failed.";
    }
}

if (window.location.pathname.startsWith("/download/")) {
    document.body.innerHTML = `
        <h1>DeadDrop</h1>
        <p>Encrypted file received.</p>
        <div id="result"></div>
        <button onclick="downloadFile()">Decrypt and Download</button>
    `;
}
</script>

</body>
</html>
"""


@app.post("/upload")
async def upload(
    file: UploadFile = File(...),
    name: str = ""
):
    cleanup()

    token = secrets.token_urlsafe(32)

    data = await file.read()


    path = STORAGE / f"{token}.bin"

    path.write_bytes(data)

    metadata[token] = {
        "name": name or "download",
        "expires": int(time.time()) + 86400
    }

    save_metadata()

    return {
        "token": token
    }


@app.get("/blob/{token}")
async def blob(token: str):
    cleanup()

    if token not in metadata:
        raise HTTPException(
            status_code=404,
            detail="Not found"
        )

    path = STORAGE / f"{token}.bin"

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail="Not found"
        )

    return Response(
        content=path.read_bytes(),
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": "attachment"
        }
    )


@app.get("/info/{token}")
async def info(token: str):
    cleanup()

    if token not in metadata:
        raise HTTPException(
            status_code=404,
            detail="Not found"
        )

    return {
        "name": metadata[token]["name"]
    }


@app.get("/download/{token}", response_class=HTMLResponse)
async def download(token: str):
    cleanup()

    if token not in metadata:
        raise HTTPException(
            status_code=404,
            detail="Not found"
        )

    return """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>DeadDrop</title>
</head>
<body style="font-family:sans-serif;max-width:700px;margin:60px auto;padding:20px;">
<h1>DeadDrop</h1>
<p>This file is encrypted.</p>
<div id="result"></div>
<button onclick="downloadFile()">Decrypt and Download</button>

<script>
async function downloadFile() {
    const result = document.getElementById("result");

    const token = window.location.pathname.split("/").pop();

    const params = new URLSearchParams(
        window.location.hash.substring(1)
    );

    const keyString = params.get("key");

    if (!keyString) {
        result.innerText = "Missing decryption key.";
        return;
    }

    function fromBase64url(value) {
        value = value.replace(/-/g, "+").replace(/_/g, "/");

        while (value.length % 4) {
            value += "=";
        }

        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes;
    }

    const response = await fetch(
        "/blob/" + encodeURIComponent(token)
    );

    if (!response.ok) {
        result.innerText = "File unavailable.";
        return;
    }

    const encrypted = new Uint8Array(
        await response.arrayBuffer()
    );

    const iv = encrypted.slice(0, 12);
    const ciphertext = encrypted.slice(12);

    const key = await crypto.subtle.importKey(
        "raw",
        fromBase64url(keyString),
        {
            name: "AES-GCM"
        },
        false,
        ["decrypt"]
    );

    try {
        const plaintext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            ciphertext
        );

        const infoResponse = await fetch(
            "/info/" + encodeURIComponent(token)
        );

        const info = await infoResponse.json();

        const blob = new Blob([plaintext]);

        const link = document.createElement("a");

        link.href = URL.createObjectURL(blob);
        link.download = info.name;

        document.body.appendChild(link);
        link.click();
        link.remove();

        result.innerText = "File decrypted.";
    } catch {
        result.innerText = "Decryption failed.";
    }
}
</script>
</body>
</html>
"""
