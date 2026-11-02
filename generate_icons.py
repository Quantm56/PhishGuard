"""Generate extension icons using Pillow."""
import os
from PIL import Image, ImageDraw

def create_icon(size):
    # Create image with transparent background
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    pad = max(1, size // 10)
    w = size - 2 * pad
    h = size - 2 * pad
    
    # Shield shape points
    # Top left: (pad, pad) -> Top right: (pad + w, pad) -> Middle right: (pad + w, pad + h * 0.6)
    # -> Bottom point: (pad + w // 2, pad + h) -> Middle left: (pad, pad + h * 0.6)
    points = [
        (pad, pad + h * 0.15),
        (pad + w * 0.5, pad),
        (pad + w, pad + h * 0.15),
        (pad + w, pad + h * 0.60),
        (pad + w * 0.5, pad + h),
        (pad, pad + h * 0.60)
    ]
    
    # Draw shield background (deep navy blue #1a365d)
    draw.polygon(points, fill=(26, 54, 93, 255))
    
    # Inner shield accent (vibrant cyan/blue #3182ce)
    inner_pad = max(1, size // 8)
    iw = size - 2 * inner_pad
    ih = size - 2 * inner_pad
    inner_points = [
        (inner_pad, inner_pad + ih * 0.15),
        (inner_pad + iw * 0.5, inner_pad),
        (inner_pad + iw, inner_pad + ih * 0.15),
        (inner_pad + iw, inner_pad + ih * 0.60),
        (inner_pad + iw * 0.5, inner_pad + ih),
        (inner_pad, inner_pad + ih * 0.60)
    ]
    draw.polygon(inner_points, fill=(49, 130, 206, 255))
    
    # Draw a stylized checkmark or 'P' in center if size >= 32
    if size >= 32:
        # Checkmark
        p1 = (size * 0.32, size * 0.50)
        p2 = (size * 0.46, size * 0.65)
        p3 = (size * 0.70, size * 0.35)
        line_w = max(2, size // 12)
        draw.line([p1, p2, p3], fill=(255, 255, 255, 255), width=line_w)
    elif size >= 16:
        p1 = (size * 0.30, size * 0.50)
        p2 = (size * 0.45, size * 0.65)
        p3 = (size * 0.72, size * 0.35)
        draw.line([p1, p2, p3], fill=(255, 255, 255, 255), width=2)
        
    return img

def main():
    icons_dir = os.path.join(os.path.dirname(__file__), "extension", "icons")
    os.makedirs(icons_dir, exist_ok=True)
    for size in (16, 32, 48, 128):
        icon = create_icon(size)
        path = os.path.join(icons_dir, f"icon{size}.png")
        icon.save(path, "PNG")
        print(f"Generated {path}")

if __name__ == "__main__":
    main()

