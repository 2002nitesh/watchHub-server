import express from "express";
import { googleAuth, logout} from "../controllers/auth.js";
import { verifyToken } from "../verifyToken.js";

const router = express.Router();

//GOOGLE AUTH
router.post("/google", googleAuth)

//LOGOUT
router.post("/logout", verifyToken, logout);

export default router;
