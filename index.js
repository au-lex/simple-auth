


const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const validator = require('validator');
const fs = require('fs');
const path = require('path');
const cors = require('cors'); 


const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: ['http://localhost:5173', 'https://shop-mart-chi.vercel.app', 'http://127.0.0.1:5500'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));

const USERS_FILE = path.join(__dirname, 'users.json');


// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Helper function to read users from file
function readUsersFromFile() {
    try {
      const fileContent = fs.readFileSync('users.json', 'utf8');
      return JSON.parse(fileContent);
    } catch (error) {
      console.error(`Error reading users file: ${error}`);
      return []; // or some default value
    }
  }

// Helper function to write users to file
const writeUsersToFile = (users) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

// Welcome route
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Welcome to the Simple Auth API!' });
});

// Signup route
app.post('/signup', async (req, res) => {
    const { username, password, email } = req.body;
    const users = readUsersFromFile();

    // Validate email
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: 'Invalid email' });
    }

    // Check if user already exists
    const userExists = users.find(user => user.username === username || user.email === email);
    if (userExists) {
        return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store user
    users.push({ username, email, password: hashedPassword });
    writeUsersToFile(users);

    res.status(201).json({ message: 'User created successfully' });
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = readUsersFromFile();

    // Find user
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    res.status(200).json({ message: 'Login successful' });
});

// Get all users route
app.get('/users', (req, res) => {
    const users = readUsersFromFile();
    const userList = users.map(user => ({
        username: user.username,
        email: user.email
    }));
    res.status(200).json(userList);
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
