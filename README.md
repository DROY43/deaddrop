# DeadDrop

DeadDrop is a simple encrypted file drop.

Files are encrypted **in your browser before they are uploaded**. The server only receives the encrypted file.

## How it works

1. Open DeadDrop.
2. Choose a file.
3. Click **Encrypt and Upload**.
4. DeadDrop creates a private link.
5. Send that link to the person you want to receive the file.
6. They open the link and click **Decrypt and Download**.

The encryption key is stored in the link's `#fragment`, so it is not sent to the server in the HTTP request.

## Run DeadDrop

### 1. Clone the repository

```bash
git clone https://github.com/DROY43/deaddrop.git
cd deaddrop
```

### 2. Create a Python environment

```bash
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install fastapi uvicorn python-multipart
```

### 4. Start DeadDrop

```bash
python -m uvicorn deaddrop:app --host 127.0.0.1 --port 8000
```

Then open:

```text
http://127.0.0.1:8000
```

## Tor Onion Service

DeadDrop can also be hosted as a Tor onion service.

Example:

```text
HiddenServiceDir /var/lib/tor/deaddrop/
HiddenServicePort 80 127.0.0.1:8000
```

After configuring Tor, your onion address can be found with:

```bash
sudo cat /var/lib/tor/deaddrop/hostname
```

Open the `.onion` address using Tor Browser.

## Important

DeadDrop is currently a **prototype**.

The current version:

* Uses AES-256-GCM encryption in the browser
* Stores encrypted files on the server
* Automatically expires files after 24 hours
* Has a 100 MB upload limit
* Does not require an account
* Does not currently delete a file after its first download

Do not rely on this version for highly sensitive or life-critical information yet.

## License

See the repository for licensing information.
