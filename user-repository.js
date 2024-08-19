import dbLocal from "db-local";
import crypto from "node:crypto";
import bcrypt from "bcrypt";

import dotenv from "dotenv";

// Configura dotenv al inicio del archivo
dotenv.config();

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10); // Convertir a entero

const { Schema } = new dbLocal({ path: "./db" });
const User = Schema("User", {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  age: { type: Number, required: true },
  created_at: { type: String, require: true },
});
export class UserRepository {
  //validar tipo de dato y longitud
  static async create({ username, password, age }) {
    Validation.username(username);
    Validation.password(password);
    Validation.age(age);

    //validar usuario unico
    const user = User.findOne({ username });
    if (user) throw new Error("el usuario ya existe");

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const fecha_registro = new Date().toLocaleString();
    const photoUrl =  "/images/profile.jpg";
    const email = "emanuel@example.com"
    //guardando
    User.create({
      _id: id,
      username,
      password: hashedPassword,
      age,
      created_at: fecha_registro,
      photoUrl,
      email
    }).save();

    return id;
  }

  static async login({ username, password }) {
    Validation.username(username);
    Validation.password(password);
    const user = User.findOne({ username });
    if (!user) throw new Error("El usuario no existe");
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) throw new Error("El password es invalido");
    //no mostrar password
    const { password: _, ...publicUser } = user;
    return publicUser;
    
  }
}

class Validation {
  static username(username) {
    if (typeof username !== "string")
      throw new Error("username must be a string");
    if (username.length < 3)
      throw new Error("username must be at least 3 characters long");
  }

  static password(password) {
    if (typeof password !== "string")
      throw new Error("password must be a string");
    if (password.length < 6)
      throw new Error("password must be at least 6 characters long");
  }
  static age(age) {
    if (typeof age !== "number") throw new Error("age must be a number");
  }
}
