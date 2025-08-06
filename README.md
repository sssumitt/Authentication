# 🔐 Auth Service

A secure and scalable **Authentication and Authorization microservice** built using **Express.js** with support for **JWT**, **CSRF protection**, **cookies**, and **refresh token rotation**. Designed to be easily integrated with frontend applications hosted on different domains.

---

## 🚀 Features

- ✅ JWT-based Authentication (Access + Refresh Tokens)
- 🍪 HttpOnly & Secure Cookies with `SameSite=None`
- 🔄 Refresh Token endpoint (`/auth/refresh`)
- 🛡️ CSRF protection using `csurf`
- 🔒 Password hashing using `bcrypt`
- 🧩 Modular Token Service
- 🌐 CORS support for cross-origin frontend
- ☁️ Environment variable management using `dotenv`
- 📦 Ready for deployment (serverless / dockerizable)

---

## 🛠️ Tech Stack

- **Node.js** with **Express 5**
- **JWT (RS256 Algorithm)** for token signing
- **MongoDB** / **MySQL2** for data storage
- **bcrypt** for password hashing
- **cookie-parser** + **csurf** for cookie and CSRF handling
- **CORS** middleware for frontend-backend communication
- **dotenv** for configuration
- **Neon Serverless** / **Mongoose** for DB options

