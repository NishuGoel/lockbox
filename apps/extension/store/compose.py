# Puts the popup screenshot onto the page screenshot, top-right like a real toolbar popup.
from PIL import Image, ImageDraw, ImageFilter
import os
d = os.path.join(os.path.dirname(__file__), 'images')
base = Image.open(os.path.join(d, '4-base.png')).convert('RGBA')
pop = Image.open(os.path.join(d, '4-popup.png')).convert('RGBA')
mask = Image.new('L', pop.size, 0); ImageDraw.Draw(mask).rounded_rectangle((0, 0, *pop.size), 12, fill=255)
x, y = base.width - pop.width - 20, 12
shadow = Image.new('RGBA', base.size, (0, 0, 0, 0))
ImageDraw.Draw(shadow).rounded_rectangle((x, y + 8, x + pop.width, y + pop.height + 8), 14, fill=(0, 0, 0, 110))
base = Image.alpha_composite(base, shadow.filter(ImageFilter.GaussianBlur(14)))
base.paste(pop, (x, y), mask)
base.convert('RGB').save(os.path.join(d, '4-popup.png'))
os.remove(os.path.join(d, '4-base.png'))
