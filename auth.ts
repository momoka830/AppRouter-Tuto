import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";
import type { User } from "@/app/lib/definitions";
import bcrypt from "bcrypt";
import postgres from "postgres";

const sql = postgres(process.env.POSTGRES_URL!, { ssl: "require" });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        // ① メールとパスワードをバリデーション
        console.log("authorize called with:", credentials); // ← 追加

        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        console.log("parsedCredentials:", parsedCredentials); // ← 追加

        // ② バリデーション成功時
        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          console.log("Email from form:", email); // ← 追加

          // ③ データベースからユーザーを取得
          const user = await getUser(email);
          console.log("User from DB:", user); // ← 追加

          if (!user) {
            console.log("User not found"); // ← 追加
            return null;
          }

          // ④ パスワードが一致するか確認（bcryptで比較）
          const passwordsMatch = await bcrypt.compare(password, user.password);
          console.log("Password match result:", passwordsMatch); // ← 追加

          // ⑤ パスワードが一致したらユーザーを返す
          if (passwordsMatch) {
            console.log("Login successful!"); // ← 追加
            return user;
          }
        }

        // ⑥ 認証失敗
        console.log("Invalid credentials");
        return null;
      },
    }),
  ],
});
