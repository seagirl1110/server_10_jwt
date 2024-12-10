import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import 'dotenv/config';
import authenticateJWT from './middlewares/authenticateJWT.js';
import authorizeRole from './middlewares/authorizeRole.js';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const port = process.env.PORT || 3333;
const jwtSecret = process.env.JWT_SECRET;

let users = [
  {
    id: 1,
    username: 'Alex',
    email: 'alex@test.com',
    password: bcrypt.hashSync('alex123', 10),
    role: 'admin',
  },
  {
    id: 2,
    username: 'Max',
    email: 'max@test.com',
    password: bcrypt.hashSync('max123', 10),
    role: 'user',
  },
  {
    id: 3,
    username: 'Kate',
    email: 'kate@test.com',
    password: bcrypt.hashSync('kate123', 10),
    role: 'user',
  },
  {
    id: 4,
    username: 'Tom',
    email: 'tom@test.com',
    password: bcrypt.hashSync('tom123', 10),
    role: 'user',
  },
];

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const user = users.find((user) => user.email === email);

    if (!user) {
      res.status(401).json({ message: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      res.status(401).json({ message: 'Invalid credentials' });
    }

    delete user.password;

    const token = jwt.sign(user, jwtSecret, { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    res.status(500).send({ message: `Error server: ${error}` });
  }
});

app.put('/update-email', authenticateJWT, (req, res) => {
  const { newEmail } = req.body;

  if (!newEmail) {
    res.status(400).json({ message: 'New email is required' });
  }

  const id = req.user.id;

  const user = users.find((user) => user.id === id);

  if (!user) {
    res.status(404).json({ message: 'User not found' });
  }

  user.email = newEmail;

  res.status(200).json({ message: 'Update email is successfully' });
});

app.delete('/delete-account', authenticateJWT, (req, res) => {
  const id = req.user.id;

  const user = users.find((user) => user.id === id);

  if (!user) {
    res.status(404).json({ message: 'User not found' });
  }

  users = users.filter((user) => user.id !== id);

  console.log(user);
  console.log(users);

  res.status(200).json({ message: 'User was delete' });
});

app.put('/update-role', authenticateJWT, authorizeRole('admin'), (req, res) => {
  const { id, newRole } = req.body;

  if (!id || !newRole) {
    res.status(400).json({ message: 'Id and new role is required' });
  }

  const user = users.find((user) => user.id === id);

  if (!user) {
    res.status(404).json({ message: 'User not found' });
  }

  user.role = newRole;

  res
    .status(200)
    .json({ message: `Update role at user  with id: ${id} is successfully` });
});

app.put('/refresh-token', authenticateJWT, (req, res) => {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, jwtSecret, (err, data) => {
      if (err) {
        return res.status(403).json({ message: 'Forbidden: Invalid token' });
      }

      const { exp, iat, ...user } = data;

      const newToken = jwt.sign(user, jwtSecret, { expiresIn: '1h' });

      res.json({ newToken });
    });
  } else {
    res.status(401).json({ message: 'Unauthorized: No token' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
