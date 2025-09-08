🌌 Spxce Todo

A space-themed Todo App built with React, Node.js, Express, and MongoDB.
Stay productive while feeling like an astronaut organizing your missions! 🚀✨

🚀 Features

🔑 User Authentication (JWT-based Sign Up & Login)

✅ Private Todos (each user manages their own tasks)

📝 Add, Edit, and Delete Todos

📂 MongoDB for secure storage

🎨 Space-themed UI for a futuristic vibe

🌐 Full MERN stack app

🛠️ Tech Stack

Frontend: React, Tailwind CSS

Backend: Node.js, Express.js

Database: MongoDB (Mongoose)

Auth: JSON Web Tokens (JWT), bcrypt for password hashing

📂 Project Structure
spxce-todo/
│── client/           # React frontend
│   ├── src/
│   │   ├── pages/    # Home, Login, Register, Todos
│   │   ├── components/ 
│── server/           # Express backend
│   ├── routes/       # auth.js, todos.js
│   ├── models/       # User.js, Todo.js
│   ├── controllers/  # Business logic
│   ├── server.js     # Entry point
│── package.json
│── README.md

⚡ Getting Started
1️⃣ Clone the Repository
git clone https://github.com/venkat-2006/space-x-todo
cd spxce-todo

2️⃣ Setup Backend
cd server
npm install


Create a .env file inside server/ with:

PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key


Run backend:

npm start

3️⃣ Setup Frontend
cd client
npm install
npm run dev


Frontend runs on http://localhost:5173
 (if using Vite).

🔑 Authentication Flow

Register → User signs up → Password is hashed with bcrypt → User stored in MongoDB.

Login → Server verifies user → Generates JWT token.

Protected Routes → Todos API requires a valid JWT in request headers (Authorization: Bearer <token>).

Logout → Frontend removes JWT from local storage.


	
🚀 Future Enhancements

🔔 Push Notifications for reminders

📱 Mobile-friendly PWA version

🎮 Gamified experience (earn stars for completing tasks!)
