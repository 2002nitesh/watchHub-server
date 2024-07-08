import mongoose from "mongoose";
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { createError } from "../error.js";
import jwt from "jsonwebtoken";

export const googleAuth = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (user) {
      const token = jwt.sign({ id: user._id }, process.env.JWT, {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRY
    });
      res
        .cookie("access_token", token, {
          httpOnly: true,
        })
        .status(200)
        .json(user._doc);
    } else {
      const newUser = new User({
        ...req.body,
        fromGoogle: true,
      });
      const savedUser = await newUser.save();
      const token = jwt.sign({ id: savedUser._id }, process.env.JWT);
      res
        .cookie("access_token", token, {
          httpOnly: true,
        })
        .status(200)
        .json(savedUser._doc);
    }
  } catch (err) {
    next(err);
  }
};

export const logout = async(req, res, next) => {
  try {
    await User.findByIdAndUpdate(
        req.user.id,
        {
            $unset: {
                access_token: 1 // removes field from document
            }
        },
        { new: true }
    );
  
    const options = {
        httpOnly: true,
    };
  
    return res
        .clearCookie("access_token", options)
        .json("logout successfull!")
  } catch (error) {
    return next(createError(403, "You can logout only your account!"))
  }
};
