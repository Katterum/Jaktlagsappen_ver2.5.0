import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "jsr:@supabase/server@^1";

type Role = "viewer" | "member" | "leader" | "admin";
type Action = "list" | "upsert" | "delete-access";

interface ManageUserPayload {
  action: Action;
  teamId: string;
  userId?: string;
  memberId?: string | null;
  username?: string;
  password?: string;
  role?: Role;
  active?: boolean;
}

const ERIK_USER_ID = "5e2d1b6e-e579-4a3a-8136-3fdcabbb1fe8";
const ERIK_USERNAME = "erik";

const response = (body: Record<string, unknown>, status = 200) =>
  Response.json(body, {
    status,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    },
  });

const cleanUsername = (value: unknown) =>
  String(value || "").trim().toLowerCase().normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]/g, "");

export default {
  fetch: withSupabase({ auth: "user" }, async (req, ctx) => {
    if (req.method === "OPTIONS") {
      return new Response("ok", { headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
      }});
    }

    try {
      const body: ManageUserPayload = await req.json();
      const teamId = String(body.teamId || "").trim();
      if (!teamId) return response({ ok: false, error: "Jaktlagets ID saknas." }, 400);

      const { data: { user: caller }, error: callerError } = await ctx.supabase.auth.getUser();
      if (callerError || !caller) return response({ ok: false, error: "Du är inte inloggad." }, 401);

      const { data: callerMembership, error: callerMembershipError } = await ctx.supabaseAdmin
        .from("team_memberships").select("user_id, username, role, active")
        .eq("team_id", teamId).eq("user_id", caller.id).maybeSingle();

      if (callerMembershipError || !callerMembership || callerMembership.role !== "admin" || callerMembership.active !== true) {
        return response({ ok: false, error: "Endast en aktiv administratör får hantera användare." }, 403);
      }

      if (body.action === "list") {
        const { data, error } = await ctx.supabaseAdmin.from("team_memberships")
          .select("user_id, member_id, username, role, active, created_at")
          .eq("team_id", teamId).order("created_at", { ascending: true });
        if (error) { console.error("manage-user list error", error); return response({ ok: false, error: error.message }, 500); }
        return response({ ok: true, users: data || [] });
      }

      if (body.action === "delete-access") {
        const targetUserId = String(body.userId || "").trim();
        if (!targetUserId) return response({ ok: false, error: "Användar-ID saknas." }, 400);

        const { data: target, error: targetError } = await ctx.supabaseAdmin.from("team_memberships")
          .select("user_id, member_id, username, role, active")
          .eq("team_id", teamId).eq("user_id", targetUserId).maybeSingle();
        if (targetError) { console.error("manage-user delete lookup error", targetError); return response({ ok: false, error: targetError.message }, 500); }
        if (!target) return response({ ok: false, error: "Användaren finns inte i jaktlaget." }, 404);
        if (target.user_id === ERIK_USER_ID || target.username === ERIK_USERNAME) {
          return response({ ok: false, error: "Eriks administratörskonto kan inte tas bort." }, 403);
        }

        const { error: membershipDeleteError } = await ctx.supabaseAdmin.from("team_memberships")
          .delete().eq("team_id", teamId).eq("user_id", targetUserId);
        if (membershipDeleteError) { console.error("manage-user membership delete error", membershipDeleteError); return response({ ok: false, error: membershipDeleteError.message }, 500); }

        const { error: authDeleteError } = await ctx.supabaseAdmin.auth.admin.deleteUser(targetUserId);
        if (authDeleteError) {
          console.error("manage-user auth delete error", authDeleteError);
          return response({ ok: false, error: "Appåtkomsten togs bort, men Auth-användaren kunde inte raderas: " + authDeleteError.message }, 500);
        }
        return response({ ok: true, deleted: true, userId: targetUserId });
      }

      if (body.action !== "upsert") return response({ ok: false, error: "Okänd åtgärd." }, 400);

      const username = cleanUsername(body.username);
      const memberId = body.memberId == null || String(body.memberId).trim() === "" ? null : String(body.memberId).trim();
      const allowedRoles: Role[] = ["viewer", "member", "leader", "admin"];
      let role: Role = allowedRoles.includes(body.role as Role) ? body.role as Role : "member";
      let active = body.active !== false;
      const password = String(body.password || "");

      if (!username) return response({ ok: false, error: "Användarnamn saknas." }, 400);
      if (password && password.length < 8) return response({ ok: false, error: "Lösenordet måste vara minst 8 tecken." }, 400);

      let query = ctx.supabaseAdmin.from("team_memberships")
        .select("user_id, member_id, username, role, active").eq("team_id", teamId);
      let existingMembership = null;
      if (body.userId) {
        const { data, error } = await query.eq("user_id", body.userId).maybeSingle();
        if (error) return response({ ok: false, error: error.message }, 500);
        existingMembership = data;
      }
      if (!existingMembership) {
        const { data, error } = await ctx.supabaseAdmin.from("team_memberships")
          .select("user_id, member_id, username, role, active").eq("team_id", teamId).eq("username", username).maybeSingle();
        if (error) return response({ ok: false, error: error.message }, 500);
        existingMembership = data;
      }
      if (!existingMembership && memberId) {
        const { data, error } = await ctx.supabaseAdmin.from("team_memberships")
          .select("user_id, member_id, username, role, active").eq("team_id", teamId).eq("member_id", memberId).maybeSingle();
        if (error) return response({ ok: false, error: error.message }, 500);
        existingMembership = data;
      }

      const protectedErik = username === ERIK_USERNAME || existingMembership?.username === ERIK_USERNAME || existingMembership?.user_id === ERIK_USER_ID;
      if (protectedErik) { role = "admin"; active = true; }

      let userId = existingMembership?.user_id || null;
      if (!userId) {
        if (!password) return response({ ok: false, error: "Ett lösenord krävs när en ny användare skapas." }, 400);
        const { data: created, error } = await ctx.supabaseAdmin.auth.admin.createUser({
          email: `${username}@katterums-jaktlag.invalid`, password, email_confirm: true,
          user_metadata: { username, team_id: teamId },
        });
        if (error || !created.user) return response({ ok: false, error: error?.message || "Auth-användaren kunde inte skapas." }, 400);
        userId = created.user.id;
      } else if (password) {
        const { error } = await ctx.supabaseAdmin.auth.admin.updateUserById(userId, { password });
        if (error) return response({ ok: false, error: error.message }, 400);
      }

      const values = { team_id: teamId, user_id: userId, member_id: memberId, username, role, active };
      const result = existingMembership
        ? await ctx.supabaseAdmin.from("team_memberships").update(values).eq("team_id", teamId).eq("user_id", userId)
        : await ctx.supabaseAdmin.from("team_memberships").insert(values);
      if (result.error) return response({ ok: false, error: result.error.message }, 500);

      return response({ ok: true, user: { user_id: userId, member_id: memberId, username, role, active } });
    } catch (error) {
      console.error("manage-user unexpected error", error);
      return response({ ok: false, error: error instanceof Error ? error.message : "Användaråtgärden kunde inte behandlas." }, 500);
    }
  }),
};
