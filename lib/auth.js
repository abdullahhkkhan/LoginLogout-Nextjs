import { cookies } from "next/headers";
import db from "./db";

const { BetterSqlite3Adapter } = require("@lucia-auth/adapter-sqlite");
const { Lucia } = require("lucia");


const adapter = new BetterSqlite3Adapter(db, {
    user: 'users',
    session: 'sessions',
});
const lucia = new Lucia(adapter, {
    sessionCookie: {
        expires: false,
        attributes: {
            secure: process.env.NODE_ENV === 'production'
        }
    }
});

export async function createAuthSession(userID) {
    const session = await lucia.createSession(userID, {});
    const sessionCookie = lucia.createSessionCookie(session.id);
    (await cookies()).set(
        sessionCookie.name, 
        sessionCookie.value, 
        sessionCookie.attributes
    );
}

export async function verifyAuth() {
   const sessionCookie = (await cookies()).get(lucia.sessionCookieName);

   if (!sessionCookie) {
    return{
        user: null,
        session: null
    };
   }

   const sessionId = sessionCookie.value;
   
   if (!sessionId) {
    return{
        user: null,
        session: null
     };
    }

    const result = await lucia.validateSession(sessionId);

    try {
        if (result.session && result.session.fresh) {
        const sessionCookie = lucia.createSessionCookie(result.session.id);
        (await cookies()).set(
                sessionCookie.name, 
                sessionCookie.value, 
                sessionCookie.attributes
            );
        }
        if (!result.session) {
            const sessionCookie = lucia.createBlankSessionCookie();
            (await cookies()).set(
                sessionCookie.name, 
                sessionCookie.value, 
                sessionCookie.attributes
            );
        }
    } catch {}

    return result;
}

export async function destroySession() {
    const { session } = await verifyAuth();
    if (!session) {
        return{
            error: 'Unauthorised!'
        }
    }

    await lucia.invalidateSession(session.id)

    const sessionCookie = lucia.createBlankSessionCookie();
    (await cookies()).set(
        sessionCookie.name, 
        sessionCookie.value, 
        sessionCookie.attributes
    );

}