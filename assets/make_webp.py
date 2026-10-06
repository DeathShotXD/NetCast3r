"""Rebuild the webp derivatives from NetCast3r-Logo.png and NetCast3r-Banner.png."""

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent
TOP = ROOT.parent
DASH = TOP / "src" / "netcast3r" / "dashboard"

LOGO = ROOT / "NetCast3r-Logo.png"
BANNER = ROOT / "NetCast3r-Banner.png"


def logo(size: int) -> Image.Image:
    image = Image.open(LOGO).convert("RGBA")
    box = image.split()[-1].getbbox()
    if box:
        image = image.crop(box)
    return image.resize((size, size), Image.LANCZOS)


def banner(width: int) -> Image.Image:
    image = Image.open(BANNER).convert("RGB")
    height = round(image.height * width / image.width)
    return image.resize((width, height), Image.LANCZOS)


def write(path: Path, image: Image.Image, quality: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, "WEBP", quality=quality, method=6)
    print(f"{path.relative_to(TOP)}  {image.size[0]}x{image.size[1]}")


def main() -> None:
    write(ROOT / "logo.webp", logo(512), 90)
    write(ROOT / "banner.webp", banner(1600), 86)
    write(DASH / "logo.webp", logo(512), 90)
    write(DASH / "banner.webp", banner(1100), 84)


if __name__ == "__main__":
    main()
