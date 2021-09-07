import { User } from "./entity/User";
import {sign} from "jsonwebtoken"

export const createAccesToken = (user: User) => {
    return sign({ userId: user.id },process.env.ACCESS_TOKEN_SECRET!, {
        expiresIn: "15h"
    });
};

export const createRefreshToken = (user: User) => {
    return sign({ userId: user.id },process.env.REFRESH_TOKEN_SECRET!, {
        expiresIn: "7d"
    });
};