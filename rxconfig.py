import reflex as rx

# Tailwind's v4 preflight reset is intentionally omitted — the RedFlag UI ships
# its own deterministic stylesheet (assets/redflag.css) ported from the
# "Executive Editorial / emerald" design direction, and we don't want a utility
# reset fighting it.
config = rx.Config(
    app_name="redflag_ui",
    plugins=[
        rx.plugins.SitemapPlugin(),
    ],
)
