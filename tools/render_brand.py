"""Render the vector originals to Home Assistant's native brand PNG assets."""

from pathlib import Path
import resvg_py


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    target = root/"custom_components"/"miot_ble_bridge"/"brand"
    target.mkdir(parents=True, exist_ok=True)
    for name, width in (("icon", 256), ("logo", 576)):
        original = (root/"assets"/(name+".svg")).read_text(encoding="utf-8-sig")
        variants = {
            name: original,
            "dark_"+name: original.replace("#1299C4", "#5BCCEE").replace("#F47925", "#FFA968").replace("#24364B", "#F1F5F9").replace("#617489", "#B8C8D9"),
        }
        for variant, svg in variants.items():
            for suffix, factor in (("", 1), ("@2x", 2)):
                png = resvg_py.svg_to_bytes(svg_string=svg, width=width*factor)
                (target/(variant+suffix+".png")).write_bytes(png)
    print("Rendered 8 native brand assets from the SVG originals")


if __name__ == "__main__":
    main()
