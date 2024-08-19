import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { UserRepository } from "./user-repository.js";
import dotenv from "dotenv";

// Cargar variables de entorno desde .env
dotenv.config();

const { PORT, SECRET_JWT_KEY } = process.env;

const app = express();
app.set("view engine", "ejs");
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

app.use((req, res, next) => {
  const token = req.cookies.access_token;
  req.session = { user: null };

  try {
    const data = jwt.verify(token, SECRET_JWT_KEY);
    req.session.user = data;
  } catch {}

  next(); // -> siguiente middleware o ruta
});

app.get("/", (req, res) => {
  const { user } = req.session;
  res.render("index", user);
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await UserRepository.login({ username, password });
    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
        age: user.age,
        created_at: user.created_at,
        photoUrl: user.photoUrl,
        email: user.email,
      },
      SECRET_JWT_KEY,
      { expiresIn: "1h" }
    );
    res
      .cookie("access_token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 1000 * 60 * 60,
      })
      .send({ user, token });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

app.post("/register", async (req, res) => {
  const { username, password, age } = req.body;
  console.log(req.body);

  try {
    const id = await UserRepository.create({ username, password, age });
    res.send({ id });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("access_token").json({ message: "Sesión terminada" });
});

app.get("/home", (req, res) => {
  const { user } = req.session;
  if (!user) return res.status(403).send("Acceso no autorizado");
 
  res.render("home", user);
});

app.listen(PORT, () => {
  console.log(`Corriendo en el puerto ${PORT}`);
});
