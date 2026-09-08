#!/usr/bin/env python3
"""
Generate Google Play Store visual assets for OmaSend.
Outputs:
- icon_512.png (512x512, 32-bit PNG)
- feature_graphic_1024x500.png (1024x500, 32-bit PNG)
"""

import math
import os
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

def create_icon():
    size = 512
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    margin = 16
    radius = 108
    bg_box = [margin, margin, size - margin, size - margin]

    bg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    bg_draw = ImageDraw.Draw(bg)
    bg_draw.rounded_rectangle(bg_box, radius=radius, fill=(13, 17, 26, 255))
    bg_draw.rounded_rectangle(bg_box, radius=radius, outline=(38, 48, 72, 255), width=3)
    img = Image.alpha_composite(img, bg)

    cx, cy = size // 2, size // 2
    overlay = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    overlay_draw = ImageDraw.Draw(overlay)

    rings = [60, 110, 160, 205]
    for r in rings:
        overlay_draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(34, 211, 238, 45), width=2)

    overlay_draw.line([cx - 210, cy, cx + 210, cy], fill=(34, 211, 238, 40), width=2)
    overlay_draw.line([cx, cy - 210, cx, cy + 210], fill=(34, 211, 238, 40), width=2)

    sweep = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    sweep_draw = ImageDraw.Draw(sweep)
    sweep_draw.pieslice([cx - 200, cy - 200, cx + 200, cy + 200], start=-65, end=-5, fill=(56, 189, 248, 35))
    overlay = Image.alpha_composite(overlay, sweep)

    overlay_draw.ellipse([cx - 36, cy - 36, cx + 36, cy + 36], fill=(15, 23, 42, 255), outline=(56, 189, 248, 255), width=3)
    overlay_draw.ellipse([cx - 16, cy - 16, cx + 16, cy + 16], fill=(56, 189, 248, 255))

    peer_nodes = [
        (cx + 105, cy - 80, (52, 211, 153, 255)),
        (cx - 115, cy + 65, (129, 140, 248, 255)),
        (cx + 60, cy + 120, (56, 189, 248, 255)),
    ]

    for px, py, color in peer_nodes:
        overlay_draw.ellipse([px - 14, py - 14, px + 14, py + 14], fill=(color[0], color[1], color[2], 50))
        overlay_draw.ellipse([px - 7, py - 7, px + 7, py + 7], fill=color)

    overlay_draw.line([cx, cy, cx + 105, cy - 80], fill=(52, 211, 153, 140), width=2)
    overlay_draw.line([cx, cy, cx - 115, cy + 65], fill=(129, 140, 248, 140), width=2)

    img = Image.alpha_composite(img, overlay)
    out_path = os.path.join(OUTPUT_DIR, "icon_512.png")
    img.save(out_path, format="PNG")
    print(f"Saved: {out_path}")

def create_feature_graphic():
    width, height = 1024, 500
    img = Image.new("RGBA", (width, height), (11, 15, 25, 255))
    draw = ImageDraw.Draw(img)

    for x in range(0, width, 40):
        draw.line([x, 0, x, height], fill=(20, 28, 48, 90), width=1)
    for y in range(0, height, 40):
        draw.line([0, y, width, y], fill=(20, 28, 48, 90), width=1)

    rcx, rcy = 760, 250
    overlay = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    overlay_draw = ImageDraw.Draw(overlay)

    radar_radii = [80, 150, 220, 290]
    for r in radar_radii:
        overlay_draw.ellipse([rcx - r, rcy - r, rcx + r, rcy + r], outline=(34, 211, 238, 40), width=2)

    overlay_draw.line([rcx - 300, rcy, rcx + 300, rcy], fill=(34, 211, 238, 35), width=2)
    overlay_draw.line([rcx, rcy - 300, rcx, rcy + 300], fill=(34, 211, 238, 35), width=2)

    sweep = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    sweep_draw = ImageDraw.Draw(sweep)
    sweep_draw.pieslice([rcx - 280, rcy - 280, rcx + 280, rcy + 280], start=-85, end=-15, fill=(56, 189, 248, 30))
    overlay = Image.alpha_composite(overlay, sweep)

    nodes = [
        (rcx, rcy, (56, 189, 248, 255)),
        (rcx + 130, rcy - 110, (52, 211, 153, 255)),
        (rcx - 140, rcy + 90, (129, 140, 248, 255)),
        (rcx + 100, rcy + 130, (244, 114, 182, 255)),
    ]

    for nx, ny, color in nodes:
        overlay_draw.ellipse([nx - 18, ny - 18, nx + 18, ny + 18], fill=(color[0], color[1], color[2], 50))
        overlay_draw.ellipse([nx - 8, ny - 8, nx + 8, ny + 8], fill=color)

    overlay_draw.line([rcx, rcy, rcx + 130, rcy - 110], fill=(52, 211, 153, 160), width=2)
    overlay_draw.line([rcx, rcy, rcx - 140, rcy + 90], fill=(129, 140, 248, 160), width=2)

    img = Image.alpha_composite(img, overlay)
    draw = ImageDraw.Draw(img)

    try:
        title_font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSans-Bold.ttf", 64)
        subtitle_font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSans.ttf", 22)
        badge_font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSans-Bold.ttf", 15)
    except Exception:
        title_font = ImageFont.load_default()
        subtitle_font = ImageFont.load_default()
        badge_font = ImageFont.load_default()

    draw.text((70, 110), "OmaSend", fill=(255, 255, 255, 255), font=title_font)
    draw.text((70, 195), "High-Performance Peer-to-Peer File & Clipboard Sharing", fill=(148, 163, 184, 255), font=subtitle_font)
    draw.text((70, 235), "Zero Cloud. Zero Telemetry. Pure Local Network.", fill=(56, 189, 248, 255), font=subtitle_font)

    badges = [
        ("LAN P2P DISCOVERY", (34, 211, 238, 255), (15, 30, 48, 220)),
        ("END-TO-END LOCAL", (52, 211, 153, 255), (15, 40, 30, 220)),
        ("LINUX & ANDROID", (129, 140, 248, 255), (25, 25, 55, 220)),
    ]

    bx = 70
    by = 310
    for text, text_col, bg_col in badges:
        bw = len(text) * 10 + 26
        bh = 36
        draw.rounded_rectangle([bx, by, bx + bw, by + bh], radius=8, fill=bg_col, outline=text_col, width=1)
        draw.text((bx + 14, by + 9), text, fill=text_col, font=badge_font)
        bx += bw + 16

    out_path = os.path.join(OUTPUT_DIR, "feature_graphic_1024x500.png")
    img.save(out_path, format="PNG")
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    create_icon()
    create_feature_graphic()
