import express from 'express';
import db from '../db.js';

const router = express.Router();

router.get('/', (req, res) => {
  const getTodos = db.prepare(`select * from todos where user_id = ?`);
  const todos = getTodos.all(req.userId);

  res.json(todos);
});

router.post('/', (req, res) => {
  const { task } = req.body;
  const insertTodo = db.prepare(`insert into todos (user_id, task) values(?, ?)`);
  const result = insertTodo.run(req.userId, task);

  res.json({ id: result.lastInsertRowid, task, completed: 0 });
});

router.put('/:id', (req, res) => {
  const { completed } = req.body;
  const { id } = req.params;

  const updatedTodo = db.prepare(`update todos set completed = ? where id = ?`);
  updatedTodo.run(completed, id);

  res.json({ message: 'Todo completed' });
});

router.delete('/:id', (req, res) => {
  const { id } = req.params;
  const userId = req.userId;
  const deleteTodo = db.prepare(`delete from todos where id = ? and user_id = ?`);
  deleteTodo.run(id, userId);

  res.send({ message: "Todo deleted" });
});

export default router;