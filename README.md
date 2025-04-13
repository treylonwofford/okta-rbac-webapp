# Okta RBAC Web App (Python + Flask)

This is a simple Python Flask demo application that showcases how to implement **Okta Authentication** with **Role-Based Access Control (RBAC)**. Users are authenticated through Okta and assigned roles (via groups claim) to restrict access to protected endpoints.

---

## 🚀 Features

- Okta OAuth2 login using OpenID Connect (OIDC)
- Role-based access to endpoints (`@requires_role` decorator)
- Session-based user login/logout
- Minimal Flask-based architecture

---

## 🛠️ Tech Stack

- Python 3.8+
- Flask
- Okta OAuth2
- PyJWT
- Requests

---

## 🧪 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/okta-rbac-webapp.git
cd okta-rbac-webapp
```

### 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create `.env` file

Create a `.env` file or export the following environment variables:

```bash
OKTA_DOMAIN=your_okta_domain.okta.com
OKTA_CLIENT_ID=your_client_id
OKTA_CLIENT_SECRET=your_client_secret
OKTA_REDIRECT_URI=http://localhost:5000/callback
APP_SECRET_KEY=your_secret_key
```

### 5. Run the app

```bash
flask run
```

App will be running at [http://localhost:5000](http://localhost:5000)

---

## 🔐 Role-Based Access Example

- Users with `admin` role can access `/admin`
- Default role for all users is `viewer` if no group claim is set

You can modify roles by editing the `groups` claim mapping in your Okta admin dashboard or by modifying the fallback logic in `callback()`.

---

## 📁 File Structure

```
.
├── okta_rbac_webapp.py       # Main Flask application
├── requirements.txt          # Python dependencies
├── .env.example              # Example environment config
├── README.md                 # You're here!
```

---

## ✅ Okta Setup Instructions

1. Go to your Okta developer console.
2. Create a new OIDC app (Web type).
3. Set redirect URI to: `http://localhost:5000/callback`
4. Assign groups to users (used for roles).
5. Enable `groups` claim in ID token under Security > API > Authorization Servers > Claims.

---

## 📜 License

This project is licensed under the MIT License. Feel free to fork and modify it.

---

## 👤 Author

**Treylon Wofford**

Connect with me on [LinkedIn](https://www.linkedin.com/) or explore more projects!

