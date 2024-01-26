const prisma = require("../config/prisma")
const createError = require("../utils/createError")
const jwt = require("jsonwebtoken")
const userService = require("../service/user-service")


const authenticate = async(req,res,next) => {
    try{
        const { authorization } = req.headers;

        if(!authorization){
            return createError(401,"Unauthorized")
        }

        const arrayToken = authorization.splite(" ");
        const Token = arrayToken[1]

        if(arrayToken[0] !== "Bearer" || !Token){
            return createError(401,"Unauthorized")
        }

        const payload = jwt.verify(Token,process.env.JWT_SECRET)

        if(typeof(payload) !== "object" || !payload.id ||typeof(payload.id) !== "string"){
            return createError(400,"payload incorrect format")
        }

        const user = await userService.getUserById(payload.id)
        
        if(!user){
            return createError(400,"user not found")
        }

        req.user = user;
        next();

    } catch (err) {
        next(err)
    }
}