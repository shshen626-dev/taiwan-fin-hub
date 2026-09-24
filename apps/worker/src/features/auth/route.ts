import type { Context } from "hono";
import {
  clearSessionCookie,
  createSessionCookie,
  isAppPasswordAuthConfigured,
  passwordMatches,
} from "../../platform/app-auth";
import type { AppBindings } from "../../platform/env";
import { honoFactory } from "../../platform/hono";

export const authRoutes = honoFactory.createApp();

authRoutes.get("/login", (c) => {
  if (!isAppPasswordAuthConfigured(c.env)) return c.redirect("/");
  return loginPage(c, false);
});

authRoutes.post("/auth/login", async (c) => {
  if (!isAppPasswordAuthConfigured(c.env)) return c.notFound();

  const contentType = c.req.header("content-type") ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return c.text("Unsupported Media Type", 415);
  }

  const body = await c.req.raw.formData();
  const password = body.get("password");
  if (typeof password !== "string" || password.length > 1024) {
    return loginPage(c, true);
  }
  if (!(await passwordMatches(password, c.env))) return loginPage(c, true);

  c.header("Set-Cookie", await createSessionCookie(c.env));
  return c.redirect("/", 303);
});

authRoutes.post("/auth/logout", (c) => {
  c.header("Set-Cookie", clearSessionCookie());
  return c.redirect("/login", 303);
});

function loginPage(c: Context<AppBindings>, invalid: boolean) {
  c.header("Cache-Control", "no-store");
  c.header(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
  c.header("Referrer-Policy", "no-referrer");
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  return c.html(
    `<!doctype html>
<html lang="zh-Hant">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>登入｜不用記帳</title>
    <style>
      :root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; }
      * { box-sizing: border-box; }
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f7f6; color: #17201c; }
      main { width: min(92vw, 380px); padding: 32px; border: 1px solid #dbe3df; border-radius: 20px; background: white; box-shadow: 0 18px 50px rgb(20 46 34 / 10%); }
      h1 { margin: 0 0 8px; font-size: 1.65rem; }
      p { margin: 0 0 24px; color: #5b6862; }
      label { display: block; margin-bottom: 8px; font-weight: 650; }
      input { width: 100%; padding: 12px 14px; border: 1px solid #b8c4be; border-radius: 10px; font: inherit; }
      input:focus { outline: 3px solid #bbecd6; border-color: #16744d; }
      button { width: 100%; margin-top: 16px; padding: 12px 16px; border: 0; border-radius: 10px; background: #176b49; color: white; font: inherit; font-weight: 700; cursor: pointer; }
      .error { margin: 12px 0 0; color: #a12424; font-size: .92rem; }
    </style>
  </head>
  <body>
    <main>
      <h1>不用記帳</h1>
      <p>請輸入私人部署密碼。</p>
      <form method="post" action="/auth/login">
        <label for="password">密碼</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required autofocus />
        <button type="submit">登入</button>
        ${invalid ? '<div class="error" role="alert">密碼不正確，請再試一次。</div>' : ""}
      </form>
    </main>
  </body>
</html>`,
    invalid ? 401 : 200,
  );
}
