const { knex } = require("../database/knex");
const AppError = require("../utils/AppError");
const { compare } = require("bcryptjs");

const authConfig = require("../configs/auth")
const { sign } = require("jsonwebtoken")

const { response } = require("express");

class SessionsController { 
  async create(request, response) {
    const { email, password } = request.body;

    const user = await knex("users").where({ email }).first();

      if(!user) { 
        throw new AppError("E-mail e/ou senha incorreto.", 401);
      }

    const passwordMatched = await compare(password, user.password);

      if(!passwordMatched) { 
        throw new AppError("E-mail e/ou senha incorreto.", 401);
      }

    const { secret, expiresIn } = authConfig.jwt;
    const token = sign({}, secret, {
      secret: String(user.id),
      expiresIn
    })

    return response.json({ user, token });

      } catch(error) {
        console.error("Error na criação de sessao", error);
        return response.status(500).json({ status: "error", message: "Internal Server Error" });
      }
};

module.exports = SessionsController;