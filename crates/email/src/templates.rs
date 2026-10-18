//! Email HTML templates. Keep in sync with Octo-frontend's `src/emails/` — that's the
//! hand-maintained source; this is the copy actually sent.
//!
//! Images are real HTTPS URLs, not inline data: URIs — Gmail and most clients strip inline
//! data:image/svg+xml (and often data: images generally), so anything shown here has to be
//! fetchable. The logo lives on Cloudinary; the small icon set is served from octohq.org/email/
//! (Octo-frontend's public/email/).
//!
//! ## Escaping convention
//!
//! Every value that originates outside this server — user input (email address, labels), a
//! user-signed transaction (asset code, destination), or a Horizon response (tx hash, error
//! detail) — MUST go through [`html_escape`] before it is interpolated into HTML. Only values
//! the server generates itself (the numeric OTP, the formatted amount, fixed copy) skip it.

const BURGUNDY: &str = "#7b1733";
const BURGUNDY_BRIGHT: &str = "#b81f4d";
const INK: &str = "#0a0506";

const LOGO_URL: &str =
    "https://res.cloudinary.com/h9jpvcxe/image/upload/v1786115234/octopus_burgundy_black_bg_wrx0sf.png";
const ICON_BASE: &str = "https://octohq.org/email";

/// A purpose icon shown above the body copy: a colored circle badge with a glyph.
enum Icon {
    Key,
    Wave,
    Check,
    Warn,
}

fn icon_url(icon: Icon) -> &'static str {
    match icon {
        Icon::Key => "icon-key.png",
        Icon::Wave => "icon-wave.png",
        Icon::Check => "icon-check.png",
        Icon::Warn => "icon-warn.png",
    }
}

/// A social icon link: white glyph on a filled burgundy circle, matching the button's brand color.
fn social_icon(icon: &str, href: &str, label: &str) -> String {
    format!(
        "<a href=\"{href}\" style=\"display:inline-block;margin:0 6px;text-decoration:none;\" aria-label=\"{label}\"><img src=\"{ICON_BASE}/social-{icon}.png\" width=\"32\" height=\"32\" alt=\"{label}\" style=\"display:block;border:0;\"/></a>"
    )
}

fn socials() -> String {
    [
        social_icon("x", "https://x.com/Octo_Hq", "X (Twitter)"),
        social_icon("instagram", "https://instagram.com/OctoHQ", "Instagram"),
        social_icon(
            "linkedin",
            "https://linkedin.com/company/OctoHQ",
            "LinkedIn",
        ),
        social_icon("github", "https://github.com/Octo-Protocol-org", "GitHub"),
        social_icon("telegram", "https://t.me/OctoHQ", "Telegram"),
    ]
    .join("")
}

/// Escape `&`, `<`, `>`, `"` and `'` so an untrusted value renders as text in HTML body and
/// attribute contexts, never as markup.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

fn shell(body: &str, icon: Icon) -> String {
    let icon_url = format!("{ICON_BASE}/{}", icon_url(icon));
    let socials = socials();
    let year = chrono::Utc::now().format("%Y");
    format!(
        "<div style=\"font-family:-apple-system,Helvetica,Arial,sans-serif;background:#f5f5f5;padding:32px 0;\">\
<div style=\"max-width:480px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;border:1px solid #eee;\">\
<div style=\"text-align:center;padding:28px 32px 20px;\">\
<img src=\"{LOGO_URL}\" width=\"40\" height=\"40\" alt=\"Octo\" style=\"display:inline-block;border-radius:10px;\"/>\
<div style=\"margin-top:10px;font-size:16px;font-weight:700;color:{INK};letter-spacing:-0.02em;\">Octo</div>\
</div>\
<div style=\"height:1px;background:#eee;\"></div>\
<div style=\"padding:32px;color:#222;font-size:14px;line-height:1.6;text-align:center;\">\
<div style=\"text-align:center;margin-bottom:20px;\"><img src=\"{icon_url}\" width=\"40\" height=\"40\" alt=\"\" style=\"display:inline-block;\"/></div>\
{body}\
</div>\
<div style=\"background:{BURGUNDY};padding:22px 32px;text-align:center;\">\
{socials}\
<p style=\"margin:14px 0 0;color:rgba(255,255,255,0.7);font-size:11px;\">© {year} Octo · Stellar-native wallet infrastructure</p>\
</div>\
</div>\
</div>"
    )
}

/// One-time code email, shared by signup verification and withdrawal confirmation.
pub fn otp_email(code: &str, purpose: &str) -> String {
    let action = match purpose {
        "withdrawal" => "confirm a withdrawal",
        "password_reset" => "reset your password",
        "email_change" => "confirm your new email address",
        _ => "verify your email",
    };
    shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Your verification code</p>\
<p style=\"margin:0 0 20px;color:#666;\">Use this code to {action}.</p>\
<div style=\"display:inline-block;background:{BURGUNDY_BRIGHT};border-radius:10px;padding:14px 28px;\">\
<span style=\"font-size:30px;font-weight:700;letter-spacing:6px;color:#fff;\">{code}</span>\
</div>\
<p style=\"margin:20px 0 0;color:#999;font-size:12px;\">This code expires in 10 minutes. If you didn't request it, you can ignore this email.</p>"
        ),
        Icon::Key,
    )
}

/// Escape untrusted text for interpolation into HTML (emails are only loosely validated).
fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Sent to the OLD address after an email change, so a hijacked change is noticed.
pub fn email_changed_email(new_email: &str) -> String {
    let new_email = escape_html(new_email);
    shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Your login email was changed</p>\
<p style=\"margin:0;color:#666;\">This account's email is now {new_email}. If this wasn't you, reset your password right away.</p>"
        ),
        Icon::Warn,
    )
}

/// Sent once, right after signup verification succeeds.
pub fn welcome_email(email: &str) -> String {
    // The address is user-supplied at signup; RFC 5322 local parts may legally contain `<"'&`.
    let email = html_escape(email);
    shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Welcome to Octo 🎉</p>\
<p style=\"margin:0 0 20px;color:#666;\">{email} is verified and ready to go.</p>\
<a href=\"https://octohq.org/dashboard\" style=\"display:inline-block;background:{BURGUNDY_BRIGHT};border-radius:10px;padding:12px 28px;color:#fff;font-weight:600;text-decoration:none;font-size:14px;\">Go to dashboard</a>"
        ),
        Icon::Wave,
    )
}

/// Sent after a withdrawal successfully relays to Horizon.
pub fn withdrawal_success_email(
    amount: &str,
    asset: &str,
    destination: &str,
    tx_hash: &str,
) -> String {
    // Asset and destination come from the user-signed XDR, the hash from Horizon's response.
    let (asset, destination, tx_hash) = (
        html_escape(asset),
        html_escape(destination),
        html_escape(tx_hash),
    );
    shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Withdrawal confirmed</p>\
<p style=\"margin:0 0 20px;color:#666;\">Your withdrawal has been confirmed on-chain.</p>\
<div style=\"text-align:left;background:#fafafa;border-radius:10px;padding:16px 20px;font-size:13px;\">\
<p style=\"margin:0 0 8px;\"><strong>Amount:</strong> {amount} {asset}</p>\
<p style=\"margin:0 0 8px;word-break:break-all;\"><strong>Destination:</strong> {destination}</p>\
<p style=\"margin:0;word-break:break-all;\"><strong>Transaction:</strong> {tx_hash}</p>\
</div>"
        ),
        Icon::Check,
    )
}

/// Sent when a withdrawal was attempted but did not complete (wrong OTP, or Horizon rejected it).
pub fn withdrawal_failed_email(
    amount: &str,
    asset: &str,
    destination: &str,
    reason: &str,
) -> String {
    // Asset and destination come from the user-signed XDR, the reason may echo Horizon's detail.
    let (asset, destination, reason) = (
        html_escape(asset),
        html_escape(destination),
        html_escape(reason),
    );
    shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Withdrawal attempt failed</p>\
<p style=\"margin:0 0 20px;color:#666;\">A withdrawal attempt on your account did not complete.</p>\
<div style=\"text-align:left;background:#fafafa;border-radius:10px;padding:16px 20px;font-size:13px;\">\
<p style=\"margin:0 0 8px;\"><strong>Amount:</strong> {amount} {asset}</p>\
<p style=\"margin:0 0 8px;word-break:break-all;\"><strong>Destination:</strong> {destination}</p>\
<p style=\"margin:0;\"><strong>Reason:</strong> {reason}</p>\
</div>\
<p style=\"margin:20px 0 0;color:#999;font-size:12px;\">If this wasn't you, secure your account and contact support.</p>"
        ),
        Icon::Warn,
    )
}
