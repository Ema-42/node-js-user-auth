import express from "express";
import { PORT, SECRET_JWT_KEY } from "./config.js";
import { UserRepository } from "./user-repository.js";
import cookieParser from "cookie-parser";

import jwt from "jsonwebtoken";

const app = express();
app.set("view engine", "ejs");
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

app.get("/", (req, res) => {
  const token = req.cookies.access_token;
  if (!token) return res.render("index");
  try {
    const data = jwt.verify(token, SECRET_JWT_KEY);
    res.render("index", data);
  } catch (error) {
    res.render("index");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await UserRepository.login({ username, password });
    const token = jwt.sign(
      { id: user._id, username: user.username },
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
app.post("/logout", (req, res) => {});

app.get("/protected", (req, res) => {
  const token = req.cookies.access_token;
  if (!token) {
    return res.status(403).send("Acceso no autorizado");
  }
  try {
    const data = jwt.verify(token, SECRET_JWT_KEY);
    res.render("protected", data);
  } catch (error) {
    res.status(401).send("Acceso no autorizado");
  }
});

app.listen(PORT, () => {
  console.log(`corriendo en el puerto ${PORT}`);
});
