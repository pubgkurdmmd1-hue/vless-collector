function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function tehran(iso) {
  try {
    return new Date(iso).toLocaleString("fa-IR", {
      timeZone: "Asia/Tehran",
      dateStyle: "medium",
      timeStyle: "medium",
    });
  } catch (e) {
    return iso;
  }
}

function remarkOf(link) {
  try {
    const h = link.split("#")[1] || "";
    return decodeURIComponent(h);
  } catch (e) {
    return "";
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const seg = url.pathname.split("/").filter(Boolean);
    if (!seg.length || seg[0] !== env.SUB_SECRET) {
      return new Response("Not found", { status: 404 });
    }
    const data = await env.RESULTS.get("results:v1", "json");
    if (!data) {
      return new Response(
        "First test is running. Try again in 10 minutes.",
        { status: 503 }
      );
    }
    const base = url.origin + "/" + seg[0];
    const r = seg[1] || "";
    const subHead = {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "Profile-Title": "VLESS Collector",
      "Profile-Update-Interval": "1",
    };
    if (r === "sub" && seg[2] === "fast") {
      return new Response(data.sub_fast || "", { headers: subHead });
    }
    if (r === "sub") {
      return new Response(data.sub_all || "", { headers: subHead });
    }
    if (r === "raw") {
      const txt = (data.configs || []).map((c) => c.link).join("\n");
      return new Response(txt, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }
    if (r === "stats") {
      const { sub_all, sub_fast, ...rest } = data;
      return new Response(JSON.stringify(rest), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }
    if (r === "") {
      return new Response(dash(data, base), {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }
    return new Response("Not found", { status: 404 });
  },
};

function dash(d, base) {
  const cfgs = d.configs || [];
  const ageMin = Math.max(
    0,
    Math.round((Date.now() - new Date(d.updated_at).getTime()) / 60000)
  );
  const stale = ageMin > 120;
  const rows = cfgs
    .map((c, i) => {
      const spd = c.speed_mbps ? c.speed_mbps + "M" : "—";
      return (
        "<tr><td>" + (i + 1) + "</td><td>" + esc(remarkOf(c.link)) +
        "</td><td>" + esc(c.ping_ms) + "ms</td><td>" + esc(spd) +
        "</td><td>" + esc(c.cc || "UN") + "</td><td>" +
        esc(c.consec || 1) + "x</td></tr>"
      );
    })
    .join("");
  return (
    "<!DOCTYPE html><html lang='fa' dir='rtl'><head><meta charset='utf-8'>" +
    "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
    "<meta name='robots' content='noindex,nofollow'>" +
    "<title>VLESS Collector</title><style>" +
    "body{font-family:Tahoma,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px}" +
    ".box{max-width:900px;margin:auto;background:#1e293b;border-radius:12px;padding:20px}" +
    "h1{font-size:20px;margin:0 0 10px}" +
    ".chips{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}" +
    ".chip{background:#334155;border-radius:8px;padding:6px 12px;font-size:13px}" +
    ".warn{background:#7c2d12;border-radius:8px;padding:8px 12px;font-size:13px;margin:10px 0}" +
    ".ok{background:#14532d;border-radius:8px;padding:8px 12px;font-size:13px;margin:10px 0}" +
    "table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}" +
    "td,th{border-bottom:1px solid #334155;padding:6px 4px;text-align:right}" +
    "th{color:#94a3b8}" +
    ".links{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}" +
    "input{flex:1;min-width:200px;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:8px;padding:8px;direction:ltr;text-align:left}" +
    "button{background:#2563eb;color:#fff;border:none;border-radius:8px;padding:8px 14px;cursor:pointer}" +
    "</style></head><body><div class='box'>" +
    "<h1>VLESS Collector</h1>" +
    "<div>آخرین تست: " + esc(tehran(d.updated_at)) + " (" + ageMin + " دقیقه پیش)</div>" +
    (stale
      ? "<div class='warn'>هشدار: بیش از ۲ ساعت از آخرین تست گذشته. وضعیت گیت‌هاب اکشن را بررسی کن.</div>"
      : "<div class='ok'>وضعیت: به‌روز</div>") +
    (d.kept_previous
      ? "<div class='warn'>اجرای آخر ناموفق بود و نتیجه قبلی نگه داشته شد.</div>"
      : "") +
    "<div class='chips'>" +
    "<span class='chip'>منتشرشده: " + (d.published ?? 0) + "</span>" +
    "<span class='chip'>سریع: " + (d.fast_count ?? 0) + "</span>" +
    "<span class='chip'>قبول‌شده: " + (d.passed ?? 0) + "</span>" +
    "<span class='chip'>دیده‌شده: " + (d.seen ?? 0) + "</span>" +
    "</div>" +
    "<div class='links'><input id='u1' readonly value='" + esc(base + "/sub") + "'>" +
    "<button onclick=\"cp('u1')\">کپی ساب</button></div>" +
    "<div class='links'><input id='u2' readonly value='" + esc(base + "/sub/fast") + "'>" +
    "<button onclick=\"cp('u2')\">کپی ساب سریع</button></div>" +
    "<table><tr><th>#</th><th>کانفیگ</th><th>پینگ</th><th>سرعت</th><th>کشور</th><th>پایداری</th></tr>" +
    rows +
    "</table><script>" +
    "function cp(id){var el=document.getElementById(id);el.select();" +
    "if(navigator.clipboard){navigator.clipboard.writeText(el.value);}else{document.execCommand('copy');}}" +
    "</script></div></body></html>"
  );
}
