import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync(':memory:');

db.exec(`
  create table users (
    id integer primary key autoincrement,
    username text unique,
    password text
  )  
`);

db.exec(`
  create table todos (
    id integer primary key autoincrement,
    user_id integer,
    task text,
    completed boolean default 0,
    foreign key(user_id) references users(id)
  )  
`);

export default db;