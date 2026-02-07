import type { Express, Request as ExpressRequest, Response as ExpressResponse } from "express";
import { createAdminClient, createUserClient, getAuthToken } from "../lib/supabase.js";
import { getEnv, getOptionalEnv } from "../lib/env.js";
import { generateBackupCodes, generateSecret, verifyTOTP } from "../lib/totp.js";
import { createHmac } from "crypto";

function isProbablyNetworkErrorMessage(message: string | undefined): boolean {
  if (!message) return false;
  return (
    message.includes("fetch failed") ||
    message.includes("ENOTFOUND") ||
    message.includes("EAI_AGAIN") ||
    message.includes("ECONNREFUSED") ||
    message.includes("ECONNRESET") ||
    message.includes("ETIMEDOUT") ||
    message.includes("socket hang up")
  );
}

function getAuthHeader(req: ExpressRequest): string | null {
  const authHeader = req.header("Authorization") || req.header("authorization");
  return authHeader ?? null;
}

async function requireUser(req: ExpressRequest) {
  const authHeader = getAuthHeader(req);
  if (!authHeader) {
    throw new Error("No authorization header");
  }

  const supabaseUser = createUserClient(authHeader);
  const { data, error } = await supabaseUser.auth.getUser();
  if (error || !data.user) {
    throw new Error("Unauthorized");
  }

  return { user: data.user, supabaseUser };
}

function jsonError(res: ExpressResponse, status: number, message: string, includeSuccess = true) {
  if (includeSuccess) {
    return res.status(status).json({ success: false, error: message });
  }
  return res.status(status).json({ error: message });
}

async function verifyPaystackSignature(payload: string, signature: string, secret: string): Promise<boolean> {
  const hash = createHmac("sha512", secret).update(payload).digest("hex");
  return hash === signature;
}

export function registerFunctionRoutes(app: Express) {
  app.post("/api/create-group", async (req, res) => {
    try {
      const { user } = await requireUser(req);

      const {
        name,
        description = null,
        contribution_amount,
        cycle_type,
        start_date,
        max_members,
        is_public = false,
        fee_percentage = 6.25,
      } = req.body ?? {};

      if (!name || typeof name !== "string") {
        return jsonError(res, 400, "Group name is required");
      }

      if (!contribution_amount || typeof contribution_amount !== "number" || contribution_amount <= 0) {
        return jsonError(res, 400, "Contribution amount is required");
      }

      if (!cycle_type || typeof cycle_type !== "string") {
        return jsonError(res, 400, "Cycle type is required");
      }

      if (!start_date || typeof start_date !== "string") {
        return jsonError(res, 400, "Start date is required");
      }

      if (!max_members || typeof max_members !== "number" || max_members < 2) {
        return jsonError(res, 400, "Max members must be at least 2");
      }

      const supabaseAdmin = createAdminClient();

      const { data: ajo, error: ajoError } = await supabaseAdmin
        .from("ajos")
        .insert({
          name,
          description,
          contribution_amount,
          cycle_type,
          start_date,
          max_members,
          creator_id: user.id,
          status: "active",
          current_cycle: 1,
          is_public,
          fee_percentage,
        })
        .select()
        .single();

      if (ajoError || !ajo) {
        console.error("Error creating group:", ajoError);
        return jsonError(res, 500, "Failed to create group");
      }

      const { data: membership, error: membershipError } = await supabaseAdmin
        .from("memberships")
        .insert({
          ajo_id: ajo.id,
          user_id: user.id,
          position: 1,
          is_active: true,
        })
        .select("id")
        .single();

      if (membershipError) {
        console.error("Error creating membership for group creator:", membershipError);
        // Best-effort rollback to avoid orphaned groups.
        await supabaseAdmin.from("ajos").delete().eq("id", ajo.id);
        return jsonError(res, 500, "Failed to create group membership");
      }

      return res.json({ success: true, data: { group: ajo, membership_id: membership?.id ?? null } });
    } catch (error: any) {
      console.error("Error in create-group:", error);
      const status = error.message === "Unauthorized" ? 401 : 500;
      return jsonError(res, status, error.message ?? "Unknown error");
    }
  });

  app.post("/api/join-group", async (req, res) => {
    try {
      const { user } = await requireUser(req);
      const { ajo_id } = req.body ?? {};

      if (!ajo_id || typeof ajo_id !== "string") {
        return jsonError(res, 400, "Group ID is required");
      }

      const supabaseAdmin = createAdminClient();

      const { data: group, error: groupError } = await supabaseAdmin
        .from("ajos")
        .select("id, name, max_members")
        .eq("id", ajo_id)
        .single();

      if (groupError || !group) {
        return jsonError(res, 404, "Group not found");
      }

      const { count } = await supabaseAdmin
        .from("memberships")
        .select("*", { count: "exact", head: true })
        .eq("ajo_id", ajo_id)
        .eq("is_active", true);

      if (typeof count === "number" && count >= (group.max_members || 0)) {
        return jsonError(res, 400, "Group is full");
      }

      const { data: membership, error: membershipError } = await supabaseAdmin
        .from("memberships")
        .insert({
          ajo_id,
          user_id: user.id,
          position: (count || 0) + 1,
          is_active: true,
        })
        .select("id")
        .single();

      if (membershipError) {
        // Postgres unique violation
        if ((membershipError as any).code === "23505") {
          return jsonError(res, 409, "Already a member");
        }
        console.error("Error joining group:", membershipError);
        return jsonError(res, 500, "Failed to join group");
      }

      return res.json({ success: true, data: { membership_id: membership?.id ?? null, group } });
    } catch (error: any) {
      console.error("Error in join-group:", error);
      const status = error.message === "Unauthorized" ? 401 : 500;
      return jsonError(res, status, error.message ?? "Unknown error");
    }
  });

  app.post("/api/review-join-request", async (req, res) => {
    try {
      const { user } = await requireUser(req);
      const { request_id, action } = req.body ?? {};

      if (!request_id || typeof request_id !== "string") {
        return jsonError(res, 400, "Request ID is required");
      }

      if (action !== "approve" && action !== "reject") {
        return jsonError(res, 400, "Invalid action");
      }

      const supabaseAdmin = createAdminClient();

      const { data: request, error: requestError } = await supabaseAdmin
        .from("join_requests")
        .select("id, ajo_id, user_id, status")
        .eq("id", request_id)
        .single();

      if (requestError || !request) {
        return jsonError(res, 404, "Join request not found");
      }

      const { data: group, error: groupError } = await supabaseAdmin
        .from("ajos")
        .select("id, name, creator_id, max_members")
        .eq("id", request.ajo_id)
        .single();

      if (groupError || !group) {
        return jsonError(res, 404, "Group not found");
      }

      if (group.creator_id !== user.id) {
        return jsonError(res, 403, "Only the group creator can review join requests");
      }

      if (action === "approve") {
        const { count } = await supabaseAdmin
          .from("memberships")
          .select("*", { count: "exact", head: true })
          .eq("ajo_id", request.ajo_id)
          .eq("is_active", true);

        if (typeof count === "number" && count >= (group.max_members || 0)) {
          return jsonError(res, 400, "Group is full");
        }

        const { error: membershipError } = await supabaseAdmin.from("memberships").insert({
          ajo_id: request.ajo_id,
          user_id: request.user_id,
          position: (count || 0) + 1,
          is_active: true,
        });

        if (membershipError && (membershipError as any).code !== "23505") {
          console.error("Error approving join request (membership insert):", membershipError);
          return jsonError(res, 500, "Failed to approve join request");
        }
      }

      const nextStatus = action === "approve" ? "approved" : "rejected";
      const { error: updateError } = await supabaseAdmin
        .from("join_requests")
        .update({
          status: nextStatus,
          reviewed_at: new Date().toISOString(),
          reviewed_by: user.id,
        })
        .eq("id", request_id);

      if (updateError) {
        console.error("Error updating join request:", updateError);
        return jsonError(res, 500, "Failed to update join request");
      }

      return res.json({
        success: true,
        data: {
          status: nextStatus,
          group_id: group.id,
          group_name: group.name,
          user_id: request.user_id,
        },
      });
    } catch (error: any) {
      console.error("Error in review-join-request:", error);
      const status = error.message === "Unauthorized" ? 401 : 500;
      return jsonError(res, status, error.message ?? "Unknown error");
    }
  });

  app.post("/api/check-2fa-status", async (req, res) => {
    try {
      const { user_id } = req.body ?? {};
      if (!user_id) {
        return jsonError(res, 400, "User ID is required");
      }

      const supabaseAdmin = createAdminClient();
      const { data, error } = await supabaseAdmin
        .from("user_two_factor")
        .select("is_enabled")
        .eq("user_id", user_id)
        .maybeSingle();

      if (error) {
        console.error("Error checking 2FA status:", error);
        return jsonError(res, 500, "Failed to check 2FA status");
      }

      return res.json({ success: true, data: { isEnabled: data?.is_enabled || false } });
    } catch (error: any) {
      console.error("2FA status check error:", error);
      return jsonError(res, 500, error.message ?? "Unknown error");
    }
  });

  app.post("/api/totp-setup", async (req, res) => {
    try {
      const authHeader = getAuthHeader(req);
      if (!authHeader) {
        return jsonError(res, 401, "Authorization required");
      }

      const supabaseUser = createUserClient(authHeader);
      const { data: userData, error: userError } = await supabaseUser.auth.getUser();
      if (userError || !userData.user) {
        return jsonError(res, 401, "Unauthorized");
      }

      const { action, code } = req.body ?? {};
      const supabaseAdmin = createAdminClient();

      const { data: profile } = await supabaseAdmin
        .from("profiles")
        .select("email, full_name")
        .eq("user_id", userData.user.id)
        .single();

      const userEmail = profile?.email || userData.user.email;
      const appName = "AjoConnect";

      if (action === "generate") {
        const secret = generateSecret();
        const otpauthUrl = `otpauth://totp/${encodeURIComponent(appName)}:${encodeURIComponent(
          userEmail || ""
        )}?secret=${secret}&issuer=${encodeURIComponent(appName)}&algorithm=SHA1&digits=6&period=30`;

        const { error: upsertError } = await supabaseAdmin
          .from("user_two_factor")
          .upsert(
            {
              user_id: userData.user.id,
              totp_secret: secret,
              is_enabled: false,
            },
            { onConflict: "user_id" }
          );

        if (upsertError) {
          console.error("Failed to store 2FA secret:", upsertError);
          return jsonError(res, 500, "Failed to setup 2FA");
        }

        return res.json({
          success: true,
          data: {
            secret,
            otpauthUrl,
            qrCodeUrl: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(
              otpauthUrl
            )}`,
          },
        });
      }

      if (action === "enable") {
        if (!code || code.length !== 6) {
          return jsonError(res, 400, "Invalid verification code");
        }

        const { data: twoFactor } = await supabaseAdmin
          .from("user_two_factor")
          .select("totp_secret")
          .eq("user_id", userData.user.id)
          .single();

        if (!twoFactor?.totp_secret) {
          return jsonError(res, 400, "No 2FA setup found. Please generate a new secret.");
        }

        const isValid = verifyTOTP(twoFactor.totp_secret, code);
        if (!isValid) {
          return jsonError(res, 400, "Invalid code. Please try again.");
        }

        const backupCodes = generateBackupCodes();
        const { error: enableError } = await supabaseAdmin
          .from("user_two_factor")
          .update({ is_enabled: true, backup_codes: backupCodes })
          .eq("user_id", userData.user.id);

        if (enableError) {
          console.error("Failed to enable 2FA:", enableError);
          return jsonError(res, 500, "Failed to enable 2FA");
        }

        return res.json({ success: true, data: { backupCodes } });
      }

      if (action === "disable") {
        if (!code || code.length !== 6) {
          return jsonError(res, 400, "Verification code required to disable 2FA");
        }

        const { data: twoFactor } = await supabaseAdmin
          .from("user_two_factor")
          .select("totp_secret")
          .eq("user_id", userData.user.id)
          .single();

        if (!twoFactor?.totp_secret) {
          return jsonError(res, 400, "2FA is not enabled");
        }

        const isValid = verifyTOTP(twoFactor.totp_secret, code);
        if (!isValid) {
          return jsonError(res, 400, "Invalid code");
        }

        await supabaseAdmin.from("user_two_factor").delete().eq("user_id", userData.user.id);
        return res.json({ success: true });
      }

      if (action === "status") {
        const { data: twoFactor } = await supabaseAdmin
          .from("user_two_factor")
          .select("is_enabled")
          .eq("user_id", userData.user.id)
          .maybeSingle();

        return res.json({ success: true, data: { isEnabled: twoFactor?.is_enabled || false } });
      }

      return jsonError(res, 400, "Invalid action");
    } catch (error: any) {
      console.error("2FA setup error:", error);
      return jsonError(res, 500, error.message ?? "Unknown error");
    }
  });

  app.post("/api/totp-verify", async (req, res) => {
    try {
      const { user_id, code, purpose } = req.body ?? {};
      console.log(`2FA verification request for user ${user_id}, purpose: ${purpose}`);

      if (!user_id || !code) {
        return jsonError(res, 400, "User ID and code are required");
      }

      if (code.length !== 6 && code.length !== 9) {
        return jsonError(res, 400, "Invalid code format");
      }

      const supabaseAdmin = createAdminClient();
      const { data: twoFactor, error: tfError } = await supabaseAdmin
        .from("user_two_factor")
        .select("totp_secret, is_enabled, backup_codes")
        .eq("user_id", user_id)
        .maybeSingle();

      if (tfError) {
        console.error("Error fetching 2FA settings:", tfError);
        return jsonError(res, 500, "Failed to verify 2FA");
      }

      if (!twoFactor || !twoFactor.is_enabled) {
        return res.json({ success: true, data: { verified: true, twoFactorRequired: false } });
      }

      if (code.includes("-") && code.length === 9) {
        const backupCodes = twoFactor.backup_codes || [];
        const codeIndex = backupCodes.indexOf(code.toUpperCase());

        if (codeIndex !== -1) {
          const updatedCodes = backupCodes.filter((_: string, i: number) => i !== codeIndex);
          await supabaseAdmin
            .from("user_two_factor")
            .update({ backup_codes: updatedCodes })
            .eq("user_id", user_id);

          return res.json({
            success: true,
            data: {
              verified: true,
              twoFactorRequired: true,
              backupCodeUsed: true,
              remainingBackupCodes: updatedCodes.length,
            },
          });
        }
      }

      const isValid = verifyTOTP(twoFactor.totp_secret, code);
      if (!isValid) {
        return jsonError(res, 400, "Invalid verification code");
      }

      return res.json({ success: true, data: { verified: true, twoFactorRequired: true } });
    } catch (error: any) {
      console.error("2FA verification error:", error);
      return jsonError(res, 500, error.message ?? "Unknown error");
    }
  });

  app.post("/api/send-notification", async (req, res) => {
    try {
      const supabaseAdmin = createAdminClient();
      const payload = req.body ?? {};
      const { user_id, type, title, message, data = {}, send_email = true, send_push = true } = payload;

      const { error: insertError } = await supabaseAdmin.from("notifications").insert({
        user_id,
        type,
        title,
        message,
        data,
      });

      if (insertError) {
        console.error("Error inserting notification:", insertError);
        throw insertError;
      }

      const [prefsResult, profileResult] = await Promise.all([
        supabaseAdmin
          .from("notification_preferences")
          .select("*")
          .eq("user_id", user_id)
          .maybeSingle(),
        supabaseAdmin.from("profiles").select("email, full_name").eq("user_id", user_id).single(),
      ]);

      const preferences = prefsResult.data;
      const profile = profileResult.data;

      if (!profile) {
        return res.status(200).json({ success: true, email_sent: false, push_sent: false });
      }

      let emailSent = false;
      let pushSent = false;

      const emailTemplates: Record<
        string,
        (data: any) => { subject: string; html: string }
      > = {
        group_invite: (data: any) => ({
          subject: "You've been invited to join a group on AjoConnect",
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
              <h1 style="color: #10B981;">Group Invitation</h1>
              <p>Hi ${data.user_name},</p>
              <p>${data.message}</p>
              <p style="margin-top: 24px;">
                <a href="https://getget.lovable.app/dashboard/groups" 
                   style="background: #10B981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px;">
                  View Invitation
                </a>
              </p>
              <p style="color: #6B7280; margin-top: 24px; font-size: 14px;">
                — The AjoConnect Team
              </p>
            </div>
          `,
        }),
        contribution_reminder: (data: any) => ({
          subject: "Contribution Reminder - AjoConnect",
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
              <h1 style="color: #F59E0B;">Contribution Reminder</h1>
              <p>Hi ${data.user_name},</p>
              <p>${data.message}</p>
              <p style="margin-top: 24px;">
                <a href="https://getget.lovable.app/dashboard/groups" 
                   style="background: #10B981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px;">
                  View Groups
                </a>
              </p>
              <p style="color: #6B7280; margin-top: 24px; font-size: 14px;">
                — The AjoConnect Team
              </p>
            </div>
          `,
        }),
        payment_success: (data: any) => ({
          subject: "Payment Successful - AjoConnect",
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
              <h1 style="color: #10B981;">Payment Successful</h1>
              <p>Hi ${data.user_name},</p>
              <p>${data.message}</p>
              <p style="margin-top: 24px;">
                <a href="https://getget.lovable.app/dashboard/transactions" 
                   style="background: #10B981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px;">
                  View Transactions
                </a>
              </p>
              <p style="color: #6B7280; margin-top: 24px; font-size: 14px;">
                — The AjoConnect Team
              </p>
            </div>
          `,
        }),
        payout_received: (data: any) => ({
          subject: "You've Received a Payout! - AjoConnect",
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
              <h1 style="color: #10B981;">🎉 Payout Received!</h1>
              <p>Hi ${data.user_name},</p>
              <p>${data.message}</p>
              <p style="margin-top: 24px;">
                <a href="https://getget.lovable.app/dashboard/wallet" 
                   style="background: #10B981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px;">
                  View Wallet
                </a>
              </p>
              <p style="color: #6B7280; margin-top: 24px; font-size: 14px;">
                — The AjoConnect Team
              </p>
            </div>
          `,
        }),
        referral_bonus: (data: any) => ({
          subject: "Referral Bonus Earned! - AjoConnect",
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
              <h1 style="color: #8B5CF6;">🎁 Referral Bonus!</h1>
              <p>Hi ${data.user_name},</p>
              <p>${data.message}</p>
              <p style="margin-top: 24px;">
                <a href="https://getget.lovable.app/dashboard/wallet" 
                   style="background: #10B981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px;">
                  View Wallet
                </a>
              </p>
              <p style="color: #6B7280; margin-top: 24px; font-size: 14px;">
                — The AjoConnect Team
              </p>
            </div>
          `,
        }),
        default: (data: any) => ({
          subject: `${data.title} - AjoConnect`,
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
              <h1 style="color: #10B981;">${data.title}</h1>
              <p>Hi ${data.user_name},</p>
              <p>${data.message}</p>
              <p style="margin-top: 24px;">
                <a href="https://getget.lovable.app/dashboard" 
                   style="background: #10B981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px;">
                  Go to Dashboard
                </a>
              </p>
              <p style="color: #6B7280; margin-top: 24px; font-size: 14px;">
                — The AjoConnect Team
              </p>
            </div>
          `,
        }),
      };

      if (send_email && preferences?.email_enabled !== false) {
        const templateFn = emailTemplates[type] || emailTemplates.default;
        const emailContent = templateFn({
          ...payload,
          user_email: profile.email,
          user_name: profile.full_name || "there",
        });

        console.log("Email sending disabled; would send:", {
          to: profile.email,
          subject: emailContent.subject,
        });
      }

      if (send_push && preferences?.push_enabled && preferences?.push_subscription) {
        console.log("Push notification would be sent here");
        pushSent = false;
      }

      return res.status(200).json({ success: true, email_sent: emailSent, push_sent: pushSent });
    } catch (error: unknown) {
      console.error("Error in send-notification function:", error);
      const message = error instanceof Error ? error.message : "Unknown error";
      return jsonError(res, 500, message, false);
    }
  });

  app.post("/api/initialize-payment", async (req, res) => {
    try {
      const authHeader = getAuthHeader(req);
      if (!authHeader) {
        throw new Error("No authorization header");
      }

      const supabaseUser = createUserClient(authHeader);
      const { data: userData, error: userError } = await supabaseUser.auth.getUser();
      if (userError || !userData.user) {
        throw new Error("Unauthorized");
      }

      const { email, amount, metadata = {}, callback_url } = req.body ?? {};
      if (!email || !amount || amount <= 0) {
        throw new Error("Invalid email or amount");
      }

      const paystackResponse = await fetch("https://api.paystack.co/transaction/initialize", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${getEnv("PAYSTACK_SECRET_KEY")}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email,
          amount,
          metadata: {
            user_id: userData.user.id,
            ...metadata,
          },
          callback_url: callback_url || getOptionalEnv("PAYMENT_CALLBACK_URL") || `${getEnv("SUPABASE_URL")}/payment-callback`,
        }),
      });

      if (!paystackResponse.ok) {
        const errorData = await paystackResponse.json();
        throw new Error(`Paystack API error: ${errorData.message || "Unknown error"}`);
      }

      const paystackData = await paystackResponse.json();

      const { error: ledgerError } = await supabaseUser
        .from("ledger")
        .insert({
          user_id: userData.user.id,
          type: "payment_initialization",
          amount,
          status: "pending",
          description: "Payment initialized",
          provider_reference: paystackData.data.reference,
          metadata: {
            email,
            access_code: paystackData.data.access_code,
            ...metadata,
          },
        });

      if (ledgerError) {
        console.error("Error logging to ledger:", ledgerError);
      }

      return res.json({
        success: true,
        data: {
          authorization_url: paystackData.data.authorization_url,
          access_code: paystackData.data.access_code,
          reference: paystackData.data.reference,
        },
      });
    } catch (error: any) {
      console.error("Error in initialize-payment:", error);
      return jsonError(res, error.message === "Unauthorized" ? 401 : 500, error.message ?? "Unknown error");
    }
  });

  app.post("/api/link-card", async (req, res) => {
    try {
      const authHeader = getAuthHeader(req);
      if (!authHeader) {
        throw new Error("No authorization header");
      }

      const supabaseUser = createUserClient(authHeader);
      const { data: userData, error: userError } = await supabaseUser.auth.getUser();
      if (userError || !userData.user) {
        throw new Error("Unauthorized");
      }

      const { data: profile, error: profileError } = await supabaseUser
        .from("profiles")
        .select("email")
        .eq("user_id", userData.user.id)
        .single();

      if (profileError || !profile?.email) {
        throw new Error("Could not find user email");
      }

      const { callback_url } = req.body ?? {};

      const paystackResponse = await fetch("https://api.paystack.co/transaction/initialize", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${getEnv("PAYSTACK_SECRET_KEY")}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: profile.email,
          amount: 10000,
          metadata: {
            user_id: userData.user.id,
            type: "card_tokenization",
          },
          callback_url,
          channels: ["card"],
        }),
      });

      const paystackData = await paystackResponse.json();
      if (!paystackData.status) {
        throw new Error(paystackData.message || "Failed to initialize payment");
      }

      return res.json({
        success: true,
        data: {
          authorization_url: paystackData.data.authorization_url,
          access_code: paystackData.data.access_code,
          reference: paystackData.data.reference,
        },
      });
    } catch (error: any) {
      console.error("Error in link-card:", error);
      return jsonError(res, error.message === "Unauthorized" ? 401 : 500, error.message ?? "Unknown error");
    }
  });

  app.post("/api/verify-payment", async (req, res) => {
    try {
      const authHeader = getAuthHeader(req);
      if (!authHeader) {
        throw new Error("No authorization header");
      }

      const supabaseUser = createUserClient(authHeader);
      const supabaseAdmin = createAdminClient();

      const { data: userData, error: userError } = await supabaseUser.auth.getUser();
      if (userError || !userData.user) {
        throw new Error("Unauthorized");
      }

      const { reference } = req.body ?? {};
      if (!reference) {
        throw new Error("Payment reference is required");
      }

      const paystackResponse = await fetch(
        `https://api.paystack.co/transaction/verify/${reference}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${getEnv("PAYSTACK_SECRET_KEY")}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (!paystackResponse.ok) {
        const errorData = await paystackResponse.json();
        throw new Error(`Paystack API error: ${errorData.message || "Unknown error"}`);
      }

      const paystackData = await paystackResponse.json();
      const transactionData = paystackData.data;

      if (transactionData.metadata?.user_id !== userData.user.id) {
        throw new Error("Unauthorized: Transaction does not belong to user");
      }

      const isCardTokenization = transactionData.metadata?.type === "card_tokenization";

      if (transactionData.status === "success") {
        if (!isCardTokenization) {
          const { data: wallet, error: fetchError } = await supabaseAdmin
            .from("wallets")
            .select("balance")
            .eq("user_id", userData.user.id)
            .single();

          if (fetchError) {
            throw new Error("Failed to fetch wallet");
          }

          const newBalance = (wallet?.balance || 0) + transactionData.amount;
          const { error: walletError } = await supabaseAdmin
            .from("wallets")
            .update({ balance: newBalance, updated_at: new Date().toISOString() })
            .eq("user_id", userData.user.id);

          if (walletError) {
            console.error("Error updating wallet:", walletError);
          }

          const { error: ledgerError } = await supabaseAdmin.from("ledger").insert({
            user_id: userData.user.id,
            type: "deposit",
            amount: transactionData.amount,
            status: "completed",
            description: "Wallet funding",
            provider_reference: reference,
            metadata: {
              channel: transactionData.channel,
              paid_at: transactionData.paid_at,
            },
          });

          if (ledgerError) {
            console.error("Error logging to ledger:", ledgerError);
          }

          await supabaseAdmin.from("wallet_transactions").insert({
            user_id: userData.user.id,
            type: "credit",
            amount: transactionData.amount,
            description: "Wallet funding via Paystack",
          });

          try {
            await sendNotificationInternal(supabaseAdmin, {
              user_id: userData.user.id,
              type: "payment_success",
              title: "Wallet Funded Successfully! 💰",
              message: `₦${(transactionData.amount / 100).toLocaleString()} has been added to your wallet.`,
              data: { amount: transactionData.amount, reference },
            });
          } catch (notifError) {
            console.error("Error sending notification:", notifError);
          }

          try {
            const { data: pendingReferral } = await supabaseAdmin
              .from("referrals")
              .select("id, referrer_id, reward_amount")
              .eq("referred_user_id", userData.user.id)
              .eq("status", "pending")
              .maybeSingle();

            if (pendingReferral) {
              const { error: rewardError } = await supabaseAdmin.rpc("process_referral_reward", {
                p_referred_user_id: userData.user.id,
              });

              if (!rewardError) {
                await sendNotificationInternal(supabaseAdmin, {
                  user_id: pendingReferral.referrer_id,
                  type: "referral_bonus",
                  title: "Referral Bonus Earned! 🎁",
                  message: `Congratulations! You earned ₦${(
                    (pendingReferral.reward_amount || 20000) / 100
                  ).toLocaleString()} for referring a friend who just made their first deposit.`,
                  data: { amount: pendingReferral.reward_amount },
                });
              }
            }
          } catch (refError) {
            console.error("Error checking/processing referral:", refError);
          }
        } else {
          const { error: ledgerError } = await supabaseAdmin.from("ledger").insert({
            user_id: userData.user.id,
            type: "card_verification",
            amount: transactionData.amount,
            status: "completed",
            description: "Card verification charge",
            provider_reference: reference,
            metadata: {
              type: "card_tokenization",
              channel: transactionData.channel,
              paid_at: transactionData.paid_at,
            },
          });

          if (ledgerError) {
            console.error("Error logging card verification to ledger:", ledgerError);
          }
        }

        if (transactionData.authorization && transactionData.authorization.reusable) {
          const auth = transactionData.authorization;
          const { data: existingCard } = await supabaseAdmin
            .from("user_cards")
            .select("id")
            .eq("user_id", userData.user.id)
            .eq("authorization_code", auth.authorization_code)
            .maybeSingle();

          if (!existingCard) {
            const { count } = await supabaseAdmin
              .from("user_cards")
              .select("*", { count: "exact", head: true })
              .eq("user_id", userData.user.id)
              .eq("is_active", true);

            const { error: cardError } = await supabaseAdmin.from("user_cards").insert({
              user_id: userData.user.id,
              authorization_code: auth.authorization_code,
              card_brand: auth.brand || auth.card_type || "Unknown",
              card_last4: auth.last4,
              exp_month: auth.exp_month,
              exp_year: auth.exp_year,
              bank_name: auth.bank,
              is_default: count === 0,
              is_active: true,
            });

            if (cardError) {
              console.error("Error saving card:", cardError);
            }
          }

          const { error: membershipError } = await supabaseAdmin
            .from("memberships")
            .update({
              authorization_code: auth.authorization_code,
              card_brand: auth.brand,
              card_last4: auth.last4,
            })
            .eq("user_id", userData.user.id)
            .is("authorization_code", null);

          if (membershipError) {
            console.error("Error saving card to membership:", membershipError);
          }
        }
      } else {
        const { error: ledgerError } = await supabaseAdmin.from("ledger").insert({
          user_id: userData.user.id,
          type: isCardTokenization ? "card_verification" : "deposit",
          amount: transactionData.amount,
          status: "failed",
          description: `Payment ${transactionData.status}`,
          provider_reference: reference,
          metadata: { gateway_response: transactionData.gateway_response },
        });

        if (ledgerError) {
          console.error("Error logging failed transaction:", ledgerError);
        }
      }

      return res.json({
        success: true,
        data: {
          status: transactionData.status,
          amount: transactionData.amount,
          reference: transactionData.reference,
          paid_at: transactionData.paid_at,
          channel: transactionData.channel,
          authorization: transactionData.authorization,
          metadata: transactionData.metadata,
        },
      });
    } catch (error: any) {
      console.error("Error in verify-payment:", error);
      const status = error.message?.includes("Unauthorized") ? 401 : 500;
      return jsonError(res, status, error.message ?? "Unknown error");
    }
  });

  app.post("/api/verify-bank-account", async (req, res) => {
    try {
      const authHeader = getAuthHeader(req);
      if (!authHeader) {
        return jsonError(res, 401, "No authorization header", false);
      }

      const supabaseUser = createUserClient(authHeader);
      const { data: userData, error: userError } = await supabaseUser.auth.getUser();
      if (userError || !userData.user) {
        return jsonError(res, 401, "Unauthorized", false);
      }

      const { action, account_number, bank_code, bank_name } = req.body ?? {};

      if (action === "list_banks") {
        const response = await fetch("https://nigerianbanks.xyz");
        const data = await response.json();

        if (!Array.isArray(data)) {
          return jsonError(res, 400, "Failed to fetch banks", false);
        }

        const banks = data.map((bank: any) => ({
          name: bank.name,
          code: bank.code,
        }));

        return res.json({ banks });
      }

      const paystackSecretKey = getOptionalEnv("PAYSTACK_SECRET_KEY");
      if (!paystackSecretKey) {
        return jsonError(res, 500, "Payment configuration missing", false);
      }

      if (action === "verify") {
        if (!account_number || !bank_code) {
          return jsonError(res, 400, "Account number and bank code required", false);
        }

        const response = await fetch(
          `https://api.paystack.co/bank/resolve?account_number=${account_number}&bank_code=${bank_code}`,
          { headers: { Authorization: `Bearer ${paystackSecretKey}` } }
        );
        const data = await response.json();

        if (!data.status) {
          return jsonError(res, 400, data.message || "Could not verify account", false);
        }

        return res.json({ account_name: data.data.account_name, account_number: data.data.account_number });
      }

      if (action === "add") {
        if (!account_number || !bank_code || !bank_name) {
          return jsonError(res, 400, "All bank details required", false);
        }

        const verifyResponse = await fetch(
          `https://api.paystack.co/bank/resolve?account_number=${account_number}&bank_code=${bank_code}`,
          { headers: { Authorization: `Bearer ${paystackSecretKey}` } }
        );
        const verifyData = await verifyResponse.json();

        if (!verifyData.status) {
          return jsonError(res, 400, verifyData.message || "Could not verify account", false);
        }

        const accountName = verifyData.data.account_name;
        const supabaseAdmin = createAdminClient();

        const { data: profile, error: profileError } = await supabaseAdmin
          .from("profiles")
          .select("full_name")
          .eq("user_id", userData.user.id)
          .single();

        if (profileError || !profile?.full_name) {
          return jsonError(
            res,
            400,
            "Please complete your profile with your full name before linking a bank account.",
            false
          );
        }

        const normalizedAccountName = normalizeForComparison(accountName);
        const normalizedProfileName = normalizeForComparison(profile.full_name);
        const similarity = calculateSimilarity(normalizedAccountName, normalizedProfileName);

        if (similarity < 0.5) {
          return res.status(400).json({
            error: `Account name "${accountName}" does not match your profile name "${profile.full_name}". You can only link bank accounts that belong to you.`,
            name_mismatch: true,
            account_name: accountName,
            profile_name: profile.full_name,
            match_score: Math.round(similarity * 100),
          });
        }

        const { data: existingForOthers } = await supabaseAdmin
          .from("linked_banks")
          .select("user_id")
          .eq("account_number", account_number)
          .eq("bank_code", bank_code)
          .neq("user_id", userData.user.id)
          .maybeSingle();

        if (existingForOthers) {
          return jsonError(res, 400, "This bank account is already linked to another user. Each account can only be linked once.", false);
        }

        const recipientResponse = await fetch("https://api.paystack.co/transferrecipient", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${paystackSecretKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            type: "nuban",
            name: accountName,
            account_number,
            bank_code,
            currency: "NGN",
          }),
        });
        const recipientData = await recipientResponse.json();

        if (!recipientData.status) {
          return jsonError(res, 400, recipientData.message || "Failed to create recipient", false);
        }

        const recipientCode = recipientData.data.recipient_code;

        const { data: existingBank } = await supabaseAdmin
          .from("linked_banks")
          .select("id")
          .eq("user_id", userData.user.id)
          .eq("account_number", account_number)
          .eq("bank_code", bank_code)
          .maybeSingle();

        if (existingBank) {
          return jsonError(res, 400, "This bank account is already linked", false);
        }

        const { count } = await supabaseAdmin
          .from("linked_banks")
          .select("*", { count: "exact", head: true })
          .eq("user_id", userData.user.id);

        const isDefault = count === 0;

        const { data: newBank, error: insertError } = await supabaseAdmin
          .from("linked_banks")
          .insert({
            user_id: userData.user.id,
            bank_name,
            bank_code,
            account_number,
            account_name: accountName,
            recipient_code: recipientCode,
            is_default: isDefault,
            is_verified: similarity >= 0.7,
            verification_method: similarity >= 0.7 ? "name_match" : null,
            verified_at: similarity >= 0.7 ? new Date().toISOString() : null,
          })
          .select()
          .single();

        if (insertError) {
          if (insertError.code === "23505") {
            return jsonError(res, 400, "This bank account is already linked to another user.", false);
          }
          return jsonError(res, 500, "Failed to save bank account", false);
        }

        return res.json({ success: true, bank: newBank, name_match_score: Math.round(similarity * 100) });
      }

      return jsonError(res, 400, "Invalid action", false);
    } catch (error: any) {
      console.error("Error:", error);
      return jsonError(res, 500, error.message ?? "An error occurred", false);
    }
  });

  app.post("/api/charge-contribution", async (req, res) => {
    try {
      const { membership_id, ajo_id, card_id } = req.body ?? {};
      if (!membership_id || !ajo_id) {
        throw new Error("membership_id and ajo_id are required");
      }

      const authHeader = getAuthHeader(req);
      if (!authHeader) {
        throw new Error("No authorization header");
      }

      const supabaseAdmin = createAdminClient();
      const token = getAuthToken(authHeader);
      const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token || "");
      if (userError || !userData.user) {
        throw new Error("Invalid user token");
      }

      const { data: membership, error: membershipError } = await supabaseAdmin
        .from("memberships")
        .select("*, ajos(*)")
        .eq("id", membership_id)
        .eq("user_id", userData.user.id)
        .single();

      if (membershipError || !membership) {
        throw new Error("Membership not found or access denied");
      }

      const ajo = membership.ajos;
      if (!ajo) {
        throw new Error("Ajo not found");
      }

      let authorizationCode: string | null = null;
      let cardBrand: string | null = null;
      let cardLast4: string | null = null;

      if (card_id) {
        const { data: card, error: cardError } = await supabaseAdmin
          .from("user_cards")
          .select("*")
          .eq("id", card_id)
          .eq("user_id", userData.user.id)
          .eq("is_active", true)
          .single();

        if (cardError || !card) {
          throw new Error("Card not found or inactive");
        }

        authorizationCode = card.authorization_code;
        cardBrand = card.card_brand;
        cardLast4 = card.card_last4;
      } else if (membership.authorization_code) {
        authorizationCode = membership.authorization_code;
        cardBrand = membership.card_brand;
        cardLast4 = membership.card_last4;
      } else {
        const { data: defaultCard, error: defaultCardError } = await supabaseAdmin
          .from("user_cards")
          .select("*")
          .eq("user_id", userData.user.id)
          .eq("is_active", true)
          .eq("is_default", true)
          .single();

        if (defaultCardError || !defaultCard) {
          throw new Error("No card available. Please add a card first.");
        }

        authorizationCode = defaultCard.authorization_code;
        cardBrand = defaultCard.card_brand;
        cardLast4 = defaultCard.card_last4;
      }

      if (!authorizationCode) {
        throw new Error("No authorization code available");
      }

      const { data: profile, error: profileError } = await supabaseAdmin
        .from("profiles")
        .select("email")
        .eq("user_id", userData.user.id)
        .single();

      if (profileError || !profile) {
        throw new Error("User profile not found");
      }

      const reference = `ajo_contrib_${membership_id}_${Date.now()}`;
      const chargeResponse = await fetch("https://api.paystack.co/transaction/charge_authorization", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${getEnv("PAYSTACK_SECRET_KEY")}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          authorization_code: authorizationCode,
          email: profile.email,
          amount: ajo.contribution_amount,
          reference,
          metadata: {
            user_id: userData.user.id,
            membership_id,
            ajo_id,
            charge_type: "ajo_contribution",
            cycle: ajo.current_cycle || 1,
          },
        }),
      });

      const chargeData = await chargeResponse.json();
      if (!chargeData.status) {
        throw new Error(chargeData.message || "Failed to charge card");
      }

      const { error: ledgerError } = await supabaseAdmin.from("ledger").insert({
        user_id: userData.user.id,
        ajo_id,
        membership_id,
        type: "contribution",
        amount: ajo.contribution_amount,
        status: chargeData.data.status === "success" ? "completed" : "pending",
        description: `Ajo contribution - ${ajo.name} (Cycle ${ajo.current_cycle || 1})`,
        provider_reference: reference,
        metadata: {
          charge_type: "ajo_contribution",
          card_brand: cardBrand,
          card_last4: cardLast4,
          paystack_reference: chargeData.data.reference,
        },
      });

      if (ledgerError) {
        console.error("Error logging to ledger:", ledgerError);
      }

      return res.json({
        success: true,
        message:
          chargeData.data.status === "success"
            ? "Contribution charged successfully"
            : "Contribution charge initiated",
        data: {
          reference,
          status: chargeData.data.status,
          amount: ajo.contribution_amount,
        },
      });
    } catch (error: any) {
      console.error("Error in charge-contribution:", error);
      return jsonError(res, 400, error.message ?? "Unknown error");
    }
  });

	  app.post("/api/initiate-transfer", async (req, res) => {
	    try {
      const PAYSTACK_SECRET_KEY = getOptionalEnv("PAYSTACK_SECRET_KEY");
      if (!PAYSTACK_SECRET_KEY) {
        throw new Error("PAYSTACK_SECRET_KEY is not configured");
      }

      const authHeader = getAuthHeader(req);
      if (!authHeader) {
        return jsonError(res, 401, "Authorization required");
      }

      const supabaseUser = createUserClient(authHeader);
      const { data: userData, error: userError } = await supabaseUser.auth.getUser();
      if (userError || !userData.user) {
        return jsonError(res, 401, "Unauthorized");
      }

      const { amount, recipient_code, reason } = req.body ?? {};

      if (!amount || amount < 10000) {
        return jsonError(res, 400, "Minimum withdrawal amount is ₦100");
      }

      if (!recipient_code) {
        return jsonError(res, 400, "Recipient code is required");
      }

      const supabaseAdmin = createAdminClient();

      const { data: linkedBank, error: bankError } = await supabaseAdmin
        .from("linked_banks")
        .select("*")
        .eq("user_id", userData.user.id)
        .eq("recipient_code", recipient_code)
        .maybeSingle();

      if (bankError || !linkedBank) {
        return jsonError(res, 400, "Invalid bank account");
      }

      const fiveSecondsAgo = new Date(Date.now() - 5000).toISOString();
      const { count: pendingCount } = await supabaseAdmin
        .from("ledger")
        .select("*", { count: "exact", head: true })
        .eq("user_id", userData.user.id)
        .eq("type", "withdrawal")
        .eq("status", "pending")
        .gte("created_at", fiveSecondsAgo);

      if (pendingCount && pendingCount > 0) {
        return jsonError(res, 429, "A withdrawal is already in progress. Please wait.");
      }

      const reference = `WD_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

      const { error: decrementError } = await supabaseAdmin.rpc("decrement_wallet_balance", {
        p_user_id: userData.user.id,
        p_amount: amount,
      });

      if (decrementError) {
        console.error("decrement_wallet_balance error:", decrementError);
        const errorMessage = decrementError.message.includes("Insufficient balance")
          ? "Insufficient balance"
          : decrementError.message.includes("Wallet not found")
          ? "Wallet not found"
          : "Failed to process withdrawal";

        if (isProbablyNetworkErrorMessage(decrementError.message)) {
          const withDetails =
            process.env.NODE_ENV !== "production" ? `Supabase request failed: ${decrementError.message}` : "Service unavailable";
          return jsonError(res, 503, withDetails);
        }

        const withDetails =
          errorMessage === "Failed to process withdrawal" && process.env.NODE_ENV !== "production"
            ? `${errorMessage}: ${decrementError.message}`
            : errorMessage;
        return jsonError(res, 400, withDetails);
      }

	      const { data: ledgerRow, error: ledgerError } = await supabaseAdmin
	        .from("ledger")
	        .insert({
	        user_id: userData.user.id,
	        type: "withdrawal",
	        amount: -amount,
	        status: "pending",
	        description: `Withdrawal to ${linkedBank.bank_name}`,
	        provider_reference: reference,
	        metadata: {
	          bank_name: linkedBank.bank_name,
	          account_number: linkedBank.account_number,
	        },
	        })
	        .select("id")
	        .single();

	      if (ledgerError) {
	        console.error("Failed to create ledger entry for withdrawal:", ledgerError);
	        await supabaseAdmin.rpc("decrement_wallet_balance", {
	          p_user_id: userData.user.id,
	          p_amount: -amount,
	        });
	        return jsonError(res, 500, "Failed to process withdrawal");
	      }

      let paystackResponse: Response;
      try {
        paystackResponse = await fetch("https://api.paystack.co/transfer", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            source: "balance",
            amount,
            recipient: recipient_code,
            reason: reason || "Wallet withdrawal",
            reference,
          }),
        });
      } catch (error: any) {
        console.error("Paystack transfer request failed:", error);
        await supabaseAdmin.rpc("decrement_wallet_balance", {
          p_user_id: userData.user.id,
          p_amount: -amount,
        });

        await supabaseAdmin
          .from("ledger")
          .update({
            status: "failed",
            metadata: { ...linkedBank, error: String(error?.message || error) },
          })
          .eq("provider_reference", reference);

        const message =
          process.env.NODE_ENV !== "production"
            ? `Paystack request failed: ${String(error?.message || error)}`
            : "Withdrawal provider unavailable";
        return jsonError(res, 502, message);
      }

      const paystackData = await paystackResponse.json();
      if (!paystackData.status) {
        const paystackMessage = String(paystackData.message || "Transfer initiation failed");
        const isStarterBusinessRestriction =
          /starter business/i.test(paystackMessage) && /third party payouts/i.test(paystackMessage);

        await supabaseAdmin.rpc("decrement_wallet_balance", {
          p_user_id: userData.user.id,
          p_amount: -amount,
        });

        await supabaseAdmin
          .from("ledger")
          .update({ status: "failed", metadata: { ...linkedBank, error: paystackData.message } })
          .eq("provider_reference", reference);

        if (isStarterBusinessRestriction) {
          return jsonError(
            res,
            403,
            "Paystack transfers are disabled for your business tier (Starter). Upgrade/verify your Paystack business to enable third‑party payouts."
          );
        }

        return jsonError(res, 400, paystackMessage);
      }

      await supabaseAdmin
        .from("ledger")
        .update({
          metadata: {
            transfer_code: paystackData.data.transfer_code,
            bank_name: linkedBank.bank_name,
            account_number: linkedBank.account_number,
          },
        })
        .eq("provider_reference", reference);

	      await supabaseAdmin.from("wallet_transactions").insert({
	        user_id: userData.user.id,
	        type: "debit",
	        amount,
	        description: `Withdrawal to ${linkedBank.bank_name} - ${linkedBank.account_number}`,
	        reference_id: ledgerRow?.id ?? undefined,
	      });

	      return res.json({
	        success: true,
	        reference,
	        transfer_code: paystackData.data.transfer_code,
	      });
	    } catch (error: any) {
	      console.error("Error in initiate-transfer:", error);
	      return jsonError(res, 500, error.message ?? "Unknown error");
	    }
	  });

  app.post("/api/process-scheduled-contributions", async (req, res) => {
    console.log("Starting scheduled contributions processing...");
    try {
      const supabase = createAdminClient();
      const paystackSecretKey = getEnv("PAYSTACK_SECRET_KEY");

      const now = new Date().toISOString();
      const { data: dueMemberships, error: queryError } = await supabase
        .from("memberships")
        .select("*, ajos(*)")
        .lte("next_debit_date", now)
        .eq("is_active", true)
        .lt("retry_count", 3);

      if (queryError) {
        throw queryError;
      }

      if (!dueMemberships || dueMemberships.length === 0) {
        return res.json({ success: true, processed: 0, message: "No memberships due" });
      }

      const results = {
        processed: 0,
        successful: 0,
        failed: 0,
        skipped: 0,
        errors: [] as string[],
      };

      for (const membership of dueMemberships as any[]) {
        try {
          if (!membership.ajos || membership.ajos.status !== "active") {
            results.skipped++;
            continue;
          }

          const { data: profile } = await supabase
            .from("profiles")
            .select("email, full_name")
            .eq("user_id", membership.user_id)
            .single();

          if (!profile?.email) {
            results.skipped++;
            results.errors.push(`No profile for membership ${membership.id}`);
            continue;
          }

          let authorizationCode = membership.authorization_code;
          let cardBrand = membership.card_brand;
          let cardLast4 = membership.card_last4;

          if (!authorizationCode) {
            const { data: userCards } = await supabase
              .from("user_cards")
              .select("*")
              .eq("user_id", membership.user_id)
              .eq("is_active", true)
              .order("is_default", { ascending: false })
              .order("created_at", { ascending: false });

            if (userCards && userCards.length > 0) {
              const selectedCard = userCards[0];
              authorizationCode = selectedCard.authorization_code;
              cardBrand = selectedCard.card_brand;
              cardLast4 = selectedCard.card_last4;
            }
          }

          if (!authorizationCode) {
            results.skipped++;
            results.errors.push(`No card for membership ${membership.id}`);
            continue;
          }

          const reference = `ajo_${membership.ajo_id}_${membership.id}_${Date.now()}`;
          const amountInKobo = membership.ajos.contribution_amount;

          const paystackResponse = await fetch(
            "https://api.paystack.co/transaction/charge_authorization",
            {
              method: "POST",
              headers: {
                Authorization: `Bearer ${paystackSecretKey}`,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({
                authorization_code: authorizationCode,
                email: profile.email,
                amount: amountInKobo,
                reference,
                metadata: {
                  charge_type: "ajo_contribution",
                  membership_id: membership.id,
                  ajo_id: membership.ajo_id,
                  ajo_name: membership.ajos.name,
                  cycle: membership.ajos.current_cycle || 1,
                  user_id: membership.user_id,
                  card_last4: cardLast4,
                  card_brand: cardBrand,
                  scheduled: true,
                },
              }),
            }
          );

          const paystackResult = await paystackResponse.json();

          if (paystackResult.status === true) {
            await supabase.from("ledger").insert({
              user_id: membership.user_id,
              ajo_id: membership.ajo_id,
              membership_id: membership.id,
              amount: amountInKobo,
              type: "debit",
              status: "pending",
              description: `Scheduled contribution for ${membership.ajos.name}`,
              provider_reference: paystackResult.data?.reference || reference,
              metadata: {
                charge_type: "ajo_contribution",
                cycle: membership.ajos.current_cycle || 1,
                scheduled: true,
                card_last4: cardLast4,
                card_brand: cardBrand,
              },
            });

            results.successful++;
          } else {
            results.failed++;
            results.errors.push(`Paystack failed for ${membership.id}: ${paystackResult.message}`);

            await supabase
              .from("memberships")
              .update({ retry_count: (membership.retry_count || 0) + 1 })
              .eq("id", membership.id);
          }

          results.processed++;
        } catch (membershipError) {
          results.failed++;
          results.errors.push(`Error for ${membership.id}: ${String(membershipError)}`);
        }
      }

      return res.json({ success: true, ...results });
    } catch (error: any) {
      console.error("Error in process-scheduled-contributions:", error);
      return jsonError(res, 500, String(error));
    }
  });

  app.post("/api/process-cycle-payout", async (req, res) => {
    console.log("Starting cycle payout processing...");
    try {
      const supabase = createAdminClient();
      const paystackSecretKey = getEnv("PAYSTACK_SECRET_KEY");

      let ajoIdFilter: string | null = null;
      if (req.body?.ajo_id) {
        ajoIdFilter = req.body.ajo_id;
      }

      let ajoQuery = supabase.from("ajos").select("*").eq("status", "active");
      if (ajoIdFilter) {
        ajoQuery = ajoQuery.eq("id", ajoIdFilter);
      }

      const { data: ajos, error: ajosError } = await ajoQuery;
      if (ajosError) {
        throw ajosError;
      }

      if (!ajos || ajos.length === 0) {
        return res.json({ success: true, processed: 0, message: "No active ajos" });
      }

      const results = {
        processed: 0,
        payouts_initiated: 0,
        skipped: 0,
        errors: [] as string[],
      };

      for (const ajo of ajos as any[]) {
        try {
          const { data: memberships, error: membersError } = await supabase
            .from("memberships")
            .select("*")
            .eq("ajo_id", ajo.id)
            .eq("is_active", true);

          if (membersError) {
            results.errors.push(`Failed to fetch memberships for ${ajo.name}`);
            continue;
          }

          if (!memberships || memberships.length === 0) {
            results.skipped++;
            continue;
          }

          const memberCount = memberships.length;
          const currentCycle = ajo.current_cycle || 1;

          const { data: completedContributions, error: contribError } = await supabase
            .from("ledger")
            .select("*")
            .eq("ajo_id", ajo.id)
            .eq("type", "debit")
            .eq("status", "completed")
            .contains("metadata", { cycle: currentCycle, charge_type: "ajo_contribution" });

          if (contribError) {
            results.errors.push(`Failed to fetch contributions for ${ajo.name}`);
            continue;
          }

          const paidUserIds = new Set(completedContributions?.map((c: any) => c.user_id) || []);
          const allMembersPaid = memberships.every((m: any) => paidUserIds.has(m.user_id));

          if (!allMembersPaid) {
            results.skipped++;
            continue;
          }

          const { data: existingPayout } = await supabase
            .from("ledger")
            .select("*")
            .eq("ajo_id", ajo.id)
            .eq("type", "payout")
            .contains("metadata", { cycle: currentCycle })
            .maybeSingle();

          if (existingPayout) {
            results.skipped++;
            continue;
          }

          let recipientUserId: string | null = null;
          const withdrawalOrder = ajo.withdrawal_order as string[] | null;

          if (withdrawalOrder && withdrawalOrder.length > 0) {
            const orderIndex = (currentCycle - 1) % withdrawalOrder.length;
            recipientUserId = withdrawalOrder[orderIndex];
          } else {
            const recipientMembership = memberships.find((m: any) => m.position === currentCycle);
            recipientUserId = recipientMembership?.user_id || null;
          }

          if (!recipientUserId) {
            results.errors.push(`No recipient for ${ajo.name} cycle ${currentCycle}`);
            continue;
          }

          const recipientMember = memberships.find((m: any) => m.user_id === recipientUserId);
          if (!recipientMember) {
            results.errors.push(`Invalid recipient for ${ajo.name}`);
            continue;
          }

          const { data: linkedBanks } = await supabase
            .from("linked_banks")
            .select("*")
            .eq("user_id", recipientUserId)
            .order("is_default", { ascending: false });

          if (!linkedBanks || linkedBanks.length === 0) {
            results.errors.push(`No bank account for payout recipient in ${ajo.name}`);
            continue;
          }

          const recipientBank = linkedBanks[0];
          if (!recipientBank.recipient_code) {
            results.errors.push(`Bank not configured for transfers in ${ajo.name}`);
            continue;
          }

          const { data: profile } = await supabase
            .from("profiles")
            .select("*")
            .eq("user_id", recipientUserId)
            .single();

          const feePercentage = ajo.fee_percentage ?? 6.25;
          const grossAmount = ajo.contribution_amount * memberCount;
          const feeAmount = Math.round((grossAmount * feePercentage) / 100);
          const netAmount = grossAmount - feeAmount;

          const reference = `PAYOUT_${ajo.id}_C${currentCycle}_${Date.now()}`;
          const paystackResponse = await fetch("https://api.paystack.co/transfer", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${paystackSecretKey}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              source: "balance",
              amount: netAmount,
              recipient: recipientBank.recipient_code,
              reason: `${ajo.name} - Cycle ${currentCycle} Payout`,
              reference,
            }),
          });

          const paystackResult = await paystackResponse.json();

          if (paystackResult.status === true) {
            const { data: ledgerData } = await supabase
              .from("ledger")
              .insert({
                user_id: recipientUserId,
                ajo_id: ajo.id,
                amount: netAmount,
                type: "payout",
                status: paystackResult.data?.status === "success" ? "completed" : "pending",
                description: `${ajo.name} - Cycle ${currentCycle} Payout`,
                provider_reference: reference,
                metadata: {
                  cycle: currentCycle,
                  member_count: memberCount,
                  gross_amount: grossAmount,
                  fee_percentage: feePercentage,
                  fee_amount: feeAmount,
                  net_amount: netAmount,
                  transfer_code: paystackResult.data?.transfer_code,
                  bank_name: recipientBank.bank_name,
                  account_number: recipientBank.account_number,
                  recipient_name: profile?.full_name,
                },
              })
              .select()
              .single();

            await supabase.from("platform_fees").insert({
              ajo_id: ajo.id,
              payout_ledger_id: ledgerData?.id || null,
              user_id: recipientUserId,
              gross_amount: grossAmount,
              fee_amount: feeAmount,
              net_amount: netAmount,
              fee_percentage: feePercentage,
              cycle: currentCycle,
            });

            const nextCycle = currentCycle + 1;
            await supabase.from("ajos").update({ current_cycle: nextCycle }).eq("id", ajo.id);

            results.payouts_initiated++;
          } else {
            results.errors.push(`Paystack failed for ${ajo.name}: ${paystackResult.message}`);

            await supabase.from("ledger").insert({
              user_id: recipientUserId,
              ajo_id: ajo.id,
              amount: netAmount,
              type: "payout",
              status: "failed",
              description: `${ajo.name} - Cycle ${currentCycle} Payout (Failed)`,
              provider_reference: reference,
              metadata: {
                cycle: currentCycle,
                gross_amount: grossAmount,
                fee_amount: feeAmount,
                net_amount: netAmount,
                error: paystackResult.message,
              },
            });
          }

          results.processed++;
        } catch (ajoError) {
          results.errors.push(`Error for ${ajo.name}: ${String(ajoError)}`);
        }
      }

      return res.json({ success: true, ...results });
    } catch (error: any) {
      console.error("Error in process-cycle-payout:", error);
      return jsonError(res, 500, String(error));
    }
  });

  app.post("/api/paystack-webhook", async (req, res) => {
    try {
      const rawBody = req.rawBody?.toString("utf8") ?? "";
      const paystackSignature = req.header("x-paystack-signature");

      if (!paystackSignature) {
        throw new Error("No signature provided");
      }

      const secret = getEnv("PAYSTACK_SECRET_KEY");
      const isValid = await verifyPaystackSignature(rawBody, paystackSignature, secret);

      if (!isValid) {
        throw new Error("Invalid signature");
      }

      const event = JSON.parse(rawBody);
      const supabase = createAdminClient();

      await supabase.from("webhook_logs").insert({
        event_type: event.event,
        payload: event,
        processed: false,
      });

      switch (event.event) {
        case "charge.success":
          await handleChargeSuccess(supabase, event.data);
          break;
        case "charge.failed":
          await handleChargeFailed(supabase, event.data);
          break;
        case "subscription.create":
        case "subscription.disable":
        case "subscription.not_renew":
          break;
        default:
          break;
      }

      await supabase
        .from("webhook_logs")
        .update({ processed: true })
        .eq("event_type", event.event)
        .eq("processed", false)
        .order("received_at", { ascending: false })
        .limit(1);

      return res.json({ received: true });
    } catch (error: any) {
      console.error("Error in paystack-webhook:", error);
      const status = error.message === "Invalid signature" ? 401 : 500;
      return res.status(status).json({ error: error.message ?? "Unknown error" });
    }
  });
}

function normalizeForComparison(name: string): string {
  return name.toLowerCase().replace(/[^a-z]/g, "");
}

function calculateSimilarity(s1: string, s2: string): number {
  if (s1.length === 0 && s2.length === 0) return 1.0;
  if (s1.length === 0 || s2.length === 0) return 0.0;

  const longer = s1.length > s2.length ? s1 : s2;
  const shorter = s1.length > s2.length ? s2 : s1;

  if (longer.includes(shorter)) return 0.8;

  let matches = 0;
  const shorterChars = shorter.split("");
  const longerChars = longer.split("");

  for (const char of shorterChars) {
    const idx = longerChars.indexOf(char);
    if (idx !== -1) {
      matches++;
      longerChars.splice(idx, 1);
    }
  }

  return matches / longer.length;
}

async function sendNotificationInternal(supabaseAdmin: any, payload: any) {
  await supabaseAdmin.from("notifications").insert({
    user_id: payload.user_id,
    type: payload.type,
    title: payload.title,
    message: payload.message,
    data: payload.data || {},
  });

  const { data: profile } = await supabaseAdmin
    .from("profiles")
    .select("email, full_name")
    .eq("user_id", payload.user_id)
    .single();

  const { data: prefs } = await supabaseAdmin
    .from("notification_preferences")
    .select("email_enabled")
    .eq("user_id", payload.user_id)
    .maybeSingle();

  if (profile && prefs?.email_enabled !== false) {
    console.log("Email sending disabled; would notify:", {
      to: profile.email,
      subject: `${payload.title} - AjoConnect`,
    });
  }
}

async function handleChargeSuccess(supabase: any, data: any) {
  const userId = data.metadata?.user_id;
  const chargeType = data.metadata?.charge_type;

  if (!userId) {
    return;
  }

  try {
    if (chargeType === "ajo_contribution") {
      await handleContributionSuccess(supabase, data);
      return;
    }

    const { data: wallet } = await supabase.from("wallets").select("balance").eq("user_id", userId).single();
    const newBalance = (wallet?.balance || 0) + data.amount;

    await supabase
      .from("wallets")
      .update({ balance: newBalance, updated_at: new Date().toISOString() })
      .eq("user_id", userId);

    await supabase.from("ledger").insert({
      user_id: userId,
      type: "deposit",
      amount: data.amount,
      status: "completed",
      description: "Payment successful (webhook)",
      provider_reference: data.reference,
      metadata: {
        channel: data.channel,
        paid_at: data.paid_at,
        ip_address: data.ip_address,
      },
    });
  } catch (error) {
    console.error("Error in handleChargeSuccess:", error);
  }
}

async function handleContributionSuccess(supabase: any, data: any) {
  const { membership_id, ajo_id } = data.metadata;

  try {
    await supabase
      .from("ledger")
      .update({
        status: "completed",
        metadata: {
          ...data.metadata,
          paid_at: data.paid_at,
          channel: data.channel,
        },
      })
      .eq("provider_reference", data.reference)
      .eq("type", "contribution");

    const { data: ajo } = await supabase.from("ajos").select("cycle_type").eq("id", ajo_id).single();

    if (ajo) {
      let nextDebitDate = new Date();
      switch (ajo.cycle_type) {
        case "weekly":
          nextDebitDate.setDate(nextDebitDate.getDate() + 7);
          break;
        case "biweekly":
          nextDebitDate.setDate(nextDebitDate.getDate() + 14);
          break;
        case "monthly":
          nextDebitDate.setMonth(nextDebitDate.getMonth() + 1);
          break;
        default:
          nextDebitDate.setMonth(nextDebitDate.getMonth() + 1);
      }

      await supabase
        .from("memberships")
        .update({ next_debit_date: nextDebitDate.toISOString(), retry_count: 0 })
        .eq("id", membership_id);
    }
  } catch (error) {
    console.error("Error in handleContributionSuccess:", error);
  }
}

async function handleChargeFailed(supabase: any, data: any) {
  const userId = data.metadata?.user_id;
  const chargeType = data.metadata?.charge_type;

  if (!userId) {
    return;
  }

  try {
    if (chargeType === "ajo_contribution") {
      await handleContributionFailed(supabase, data);
      return;
    }

    await supabase.from("ledger").insert({
      user_id: userId,
      type: "deposit",
      amount: data.amount,
      status: "failed",
      description: "Payment failed (webhook)",
      provider_reference: data.reference,
      metadata: data,
    });
  } catch (error) {
    console.error("Error in handleChargeFailed:", error);
  }
}

async function handleContributionFailed(supabase: any, data: any) {
  const { membership_id } = data.metadata;

  try {
    await supabase
      .from("ledger")
      .update({
        status: "failed",
        metadata: {
          ...data.metadata,
          failure_reason: data.gateway_response || "Payment failed",
        },
      })
      .eq("provider_reference", data.reference)
      .eq("type", "contribution");

    const { data: membership } = await supabase
      .from("memberships")
      .select("retry_count")
      .eq("id", membership_id)
      .single();

    if (membership) {
      await supabase
        .from("memberships")
        .update({ retry_count: (membership.retry_count || 0) + 1 })
        .eq("id", membership_id);
    }
  } catch (error) {
    console.error("Error in handleContributionFailed:", error);
  }
}
