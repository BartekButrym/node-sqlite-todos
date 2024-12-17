import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from '../db.js';

const router = express.Router();

router.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Encrypt the password
  const hashedPassword = bcrypt.hashSync(password, 8);

  // Save the new user and hashed password to the db
  try {
    const insertUser = db.prepare(`insert into users(username, password) values(?, ?)`);
    const result = insertUser.run(username, hashedPassword);

    // Add first default todo for the user
    const defaultTodo = `Hello 👋 Add your first todo`;
    const insertTodo = db.prepare(`insert into todos(user_id, task) values(?, ?)`);
    insertTodo.run(result.lastInsertRowid, defaultTodo);

    // Create a token
    const token = jwt.sign({ id: result.lastInsertRowid }, process.env.JWT_SECRET, { expiresIn: '24h' });

    res.json({ token });
  } catch (error) {
    console.log(error.message);
    res.sendStatus(503);
  }
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;

  try {
    const getUser = db.prepare(`select * from users where username = ?`);
    const user = getUser.get(username);

    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);

    if (!passwordIsValid) {
      return res.status(401).send({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    res.json({ token });
  } catch (error) {
    console.log(error.message);
    res.sendStatus(503);
  }
});

export default router;