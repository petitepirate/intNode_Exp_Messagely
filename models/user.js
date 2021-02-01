/** User class for message.ly */

const bcrypt = require("bcrypt");
const db = require("../db");
const ExpressError = require("../expressError");
const { BCRYPT_WORK_FACTOR, DB_URI } = require("../config");

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    let hashedPwd = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `INSERT INTO users (
        username,
        password,
        first_name,
        last_name,
        phone,
        join_at,
        last_login_at)
        VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
        RETURNING username, password, first_name, last_name, phone`,
        [username, hashedPwd, first_name, last_name, phone]);
    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      "SELECT password FROM users WHERE username = $1",
      [username]);
  let user = result.rows[0];

  return user && await bcrypt.compare(password, user.password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
         SET last_login_at = current_timestamp
         WHERE username = $1
         RETURNING username`,
      [username]);

  if (!result.rows[0]) {
    throw new ExpressError(`No such user: ${username}`, 404);
  }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const results = await db.query(
      `SELECT username, first_name, last_name, phone FROM USERS`
    )
    return results.rows
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const result = await db.query(
      `SELECT 
        username,
        first_name,
        last_name,
        phone,
        join_at,
        last_login_at
        FROM users
        WHERE username = $1`,
        [username]);
    if (result.length === 0) {
      throw new ExpressError('Username not found', 404)
    }
    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const results = await db.query(
      `SELECT 
        m.id, 
        m.from_username,
        t.username as to_username,
        t.first_name as to_first_name,
        t.last_name as to_last_name,
        t.phone as to_phone,
        m.to_username, 
        m.body, 
        m.sent_at, 
        m.read_at
      FROM messages as m
        JOIN users as t on m.to_username = t.username
      WHERE m.from_username = $1`,
      [username]);

    const messages = results.rows;

    if (!messages) {
      throw new ExpressError('No messages found', 404)
    }

    return messages.map((m) => {
      return {
        id: m.id,
        to_user: {
          username: m.to_username,
          first_name: m.to_first_name,
          last_name: m.to_last_name,
          phone: m.to_phone,
        },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at,
      }
    })
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const results = await db.query(
      `SELECT 
        m.id, 
        m.from_username,
        f.username as from_username,
        f.first_name as from_first_name,
        f.last_name as from_last_name,
        f.phone as from_phone,
        m.to_username, 
        m.body, 
        m.sent_at, 
        m.read_at
      FROM messages as m
        JOIN users as f on m.from_username = f.username
      WHERE m.to_username = $1`,
      [username]);

    const messages = results.rows;

    if (!messages) {
      throw new ExpressError('No messages found', 404)
    }

    return messages.map((m) => {
      return {
        id: m.id,
        from_user: {
          username: m.from_username,
          first_name: m.from_first_name,
          last_name: m.from_last_name,
          phone: m.from_phone,
        },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at,
      }
    })
  }
}


module.exports = User;
