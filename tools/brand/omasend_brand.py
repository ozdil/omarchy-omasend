#!/usr/bin/env python3
"""OmaSend brand kit generator.

Draws every OmaSend logo asset from two pixel grids, so all platforms share one
source: the mark sits on Omarchy's own 15x15 icon grid and the OMASEND wordmark
reuses the O, M, A letters of the Omarchy wordmark with S, E, N, D drawn on the
same 15 px grid. Colours are Omarchy's default Tokyo Night theme.

    pip install cairosvg pillow
    python3 omasend_brand.py [A|B|C] [out_dir]
"""
import sys, io, os, json
import cairosvg
from PIL import Image
MARK="""###############
#......#......#
#.######...##.#
#.#.........#.#
#.#.........#.#
#.#.........#.#
#.#.........#.#
###.........#.#
#.#.........#.#
#.#.........#.#
#.#.........#.#
#.#.........#.#
#.###########.#
#......#......#
########.######""".split('\n')
ARROW="""..#####
..#####
...####
..##.##
.##..##
##.....
#......""".split('\n')
def n(v):
    return f'{round(v,3):g}'
def grid_rects(rows, ox=0, oy=0, cell=20):
    # merge horizontal runs
    out=[]
    for y,r in enumerate(rows):
        x=0
        while x<len(r):
            if r[x]=='#':
                s=x
                while x<len(r) and r[x]=='#': x+=1
                out.append(f'M{n(ox+s*cell)} {n(oy+y*cell)}h{n((x-s)*cell)}v{n(cell)}h-{n((x-s)*cell)}z')
            else: x+=1
    return ''.join(out)
def put(base, glyph, r0, c0, ch='#'):
    b=[list(r) for r in base]
    for y,r in enumerate(glyph):
        for x,c in enumerate(r):
            if c=='#': b[r0+y][c0+x]=ch
    return [''.join(r) for r in b]
def clear(base, cells):
    b=[list(r) for r in base]
    for (y,x) in cells: b[y][x]='.'
    return [''.join(r) for r in b]

# Option A: official mark untouched + arrow in the void
A_frame=MARK
A_arrow=put(['.'*15]*15, ARROW, 4,4)
# Option B: arrow leaves through the top-right corner (frame opened)
B_frame=clear(MARK,[(y,x) for y in range(0,5) for x in range(10,15)])
B_frame=clear(B_frame,[(y,x) for y in range(0,2) for x in range(8,10)])
ARROW_B="""..#####
..#####
...####
..##.##
.##..##
##.....
#......""".split('\n')
B_arrow=put(['.'*15]*15, ARROW_B, 0,8)
# Option C: trademark-safe monogram: "S" glyph from the wordmark in a tile
S="""..#######
.########
###...###
###...###
###...##.
###...#..
###......
########.
.########
......###
..#...###
.##...###
###...###
###...###
########.
#######..""".split('\n')

def svg_mark(frame, arrow, fg, ac, bg=None, size=300, pad=0, rx=0):
    vb=300+2*pad
    bgr=f'<rect width="{vb}" height="{vb}" rx="{rx}" fill="{bg}"/>' if bg else ''
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{-pad} {-pad} {vb} {vb}" width="{size}" height="{size}">'
            + (f'<rect x="{-pad}" y="{-pad}" width="{vb}" height="{vb}" rx="{rx}" fill="{bg}"/>' if bg else '')
            + f'<path fill="{fg}" d="{grid_rects(frame)}"/>'
            + (f'<path fill="{ac}" d="{grid_rects(arrow)}"/>' if arrow else '') + '</svg>')
def svg_S(fg, ac, bg=None, size=300, pad=60, rx=0):
    # S is 9x16 cells; cell 15 -> 135x240; center in 300 box
    vb=300+2*pad; ox=(300-135)/2; oy=(300-240)/2
    s=f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{-pad} {-pad} {vb} {vb}" width="{size}" height="{size}">'
    if bg: s+=f'<rect x="{-pad}" y="{-pad}" width="{vb}" height="{vb}" rx="{rx}" fill="{bg}"/>'
    top=S[:7]; bot=S[7:]
    s+=f'<path fill="{fg}" d="{grid_rects(top,ox,oy,15)}"/><path fill="{ac}" d="{grid_rects(bot,ox,oy+7*15,15)}"/></svg>'
    return s

L={}
L['O']="""..#####..
.#######.
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
.#######.
..#####..""".split('\n')
L['M']=""".###########..
#############.
###...###...###
###...###...###
###...###...###
###...###...###
###...###...###
###...###...###
###...###...###
###...###...###
###...###...###
###...###...###
###...###...###
###...###...###
.##...###...##.
..#...###...#..""".split('\n')
L['M']=[r.ljust(15,'.') for r in L['M']]
L['M'][0]='..###########..'
L['M'][1]='.#############.'
L['A']="""..#######
.########
###...###
###...###
###...###
###...###
###...###
#########
#########
###...###
###...###
###...###
###...###
###...###
###...##.
###...#..""".split('\n')
L['S']=S
L['E']="""..#######
.########
###......
###......
###......
###......
###......
#######..
#######..
###......
###......
###......
###......
###......
#########
########.""".split('\n')
L['N']="""..#####..
.#######.
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...##.
###...#..""".split('\n')
L['D']="""#######..
########.
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
###...###
########.
#######..""".split('\n')
for k,v in L.items(): assert len(v)==16 and len(set(map(len,v)))==1,(k,[len(r) for r in v])
def word(text, cell=15, gap=2):
    x=0; parts=[]
    for ch in text:
        g=L[ch]; parts.append((ch,x)); x+=len(g[0])+gap
    return parts, x-gap
def svg_word(text, colors, cell=15, height=None, pad=0, bg=None):
    parts,w=word(text)
    W=w*cell+2*pad; H=16*cell+2*pad
    s=f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">'
    if bg: s+=f'<rect width="{W}" height="{H}" fill="{bg}"/>'
    for i,(ch,x) in enumerate(parts):
        s+=f'<path fill="{colors[i]}" d="{grid_rects(L[ch],pad+x*cell,pad,cell)}"/>'
    return s+'</svg>', W, H

BG='#1a1b26';G='#9ece6a';BL='#7aa2f7';FG='#c0caf5';LIGHT='#f5f5f0';INK='#1a1b26';LBL='#2e7de9'
A3="""..#####
....###
...##.#
..##..#
.##....
##.....
#......""".split('\n')
E=['.'*15]*15
OPT={}
OPT['A']=(MARK, put(E,A3,4,4))
bf=clear(MARK,[(y,x) for y in range(0,5) for x in range(9,15)])
bf=clear(bf,[(y,12) for y in range(2,5)]+[(2,x) for x in range(8,13)])
OPT['B']=(bf, put(E,A3,0,8))
cf=[list('.'*15) for _ in range(15)]
for y in range(15):
    for x in range(15):
        if (y==0 and x<7) or (x==0 and y<7) or (y==14 and x>7) or (x==14 and y>7): cf[y][x]='#'
OPT['C']=([''.join(r) for r in cf], put(E,A3,4,4))

OPTN=sys.argv[1] if len(sys.argv)>1 else 'A'
O=sys.argv[2] if len(sys.argv)>2 else 'omasend-brand-'+OPTN
os.makedirs(O,exist_ok=True)
f,a=OPT[OPTN]
merged=[''.join('#' if f[r][c]=='#' or a[r][c]=='#' else '.' for c in range(15)) for r in range(15)]
def w(p,s): open(f'{O}/{p}','w').write(s)
def topng(svg,out,W,H=None): cairosvg.svg2png(bytestring=svg.encode(),write_to=f'{O}/{out}',output_width=W,output_height=H or W)
app=svg_mark(f,a,G,BL,BG,pad=60,rx=84,size=512); w('omasend.svg',app)
full=svg_mark(f,a,G,BL,BG,pad=75,rx=0,size=512)  # full-bleed square (apple, play store)
mark=svg_mark(f,a,G,BL,None,pad=0,size=300); w('omasend-mark.svg',mark)
sym=svg_mark(merged,None,'currentColor',None,None,pad=0,size=16).replace('width="16" height="16"','width="16" height="16"'); w('omasend-symbolic.svg',sym)
s,Ww,Hh=svg_word('OMASEND',[FG]*3+[G]*4); w('omasend-wordmark.svg',s)
s2,_,_=svg_word('OMASEND',['currentColor']*7); w('omasend-wordmark-mono.svg',s2)
# lockup svg (dark)
def lock(fg,ac,wa,wb,bg):
    cell=15; mh=240  # mark height = wordmark height (16 cells*15)
    sc=mh/300; gap=90
    W=mh+gap+Ww; H=mh
    s=f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="-60 -60 {W+120} {H+120}" width="{(W+120)//2}" height="{(H+120)//2}">'
    if bg: s+=f'<rect x="-60" y="-60" width="{W+120}" height="{H+120}" fill="{bg}"/>'
    s+=f'<g transform="scale({sc})"><path fill="{fg}" d="{grid_rects(f)}"/><path fill="{ac}" d="{grid_rects(a)}"/></g>'
    parts,_=word('OMASEND')
    for i,(ch,x) in enumerate(parts):
        s+=f'<path fill="{wa if i<3 else wb}" d="{grid_rects(L[ch],mh+gap+x*cell,0,cell)}"/>'
    return s+'</svg>'
w('omasend-lockup-dark.svg',lock(G,BL,FG,G,None)); w('omasend-lockup-light.svg',lock(INK,'#2e7de9',INK,'#587539',None))
# feature graphic 1024x500
lk=lock(G,BL,FG,G,None)
fg=(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 500" width="1024" height="500"><rect width="1024" height="500" fill="{BG}"/>'
    f'<svg x="112" y="120" width="800" height="200" viewBox="{lk.split("viewBox=")[1].split(chr(34))[1]}">{lk.split(">",1)[1]}'
    f'<text x="512" y="390" text-anchor="middle" font-family="JetBrains Mono, DejaVu Sans Mono, monospace" font-size="30" fill="{FG}" opacity="0.8">File and clipboard sharing for Omarchy</text></svg>')
w('feature_graphic_1024x500.svg',fg)
for out,svg,W in [('omasend-512.png',app,512),('omasend-256.png',app,256),('icon-512.png',full,512),('icon-192.png',full,192),('apple-touch-icon.png',full,180),('omasend-wordmark.png',s,1024)]:
    if out=='omasend-wordmark.png': topng(svg,out,1024,int(1024*Hh/Ww))
    else: topng(svg,out,W)
topng(fg,'feature_graphic_1024x500.png',1024,500)
# Android launcher legacy png (192, round)
topng(svg_mark(f,a,G,BL,BG,pad=90,rx=0,size=192),'ic_launcher.png',192)
round_svg=svg_mark(f,a,G,BL,BG,pad=110,rx=240,size=192); topng(round_svg,'ic_launcher_round.png',192)
# Android vectors
def vec(paths,vw,vh,wdp,hdp):
    body=''.join(f'\n    <path\n        android:fillColor="{c}"\n        android:pathData="{d}" />' for c,d in paths)
    return f'<?xml version="1.0" encoding="utf-8"?>\n<!-- Generated from the OmaSend brand kit (option {OPTN}); do not edit by hand. -->\n<vector xmlns:android="http://schemas.android.com/apk/res/android"\n    android:width="{wdp}dp"\n    android:height="{hdp}dp"\n    android:viewportWidth="{vw}"\n    android:viewportHeight="{vh}">{body}\n</vector>\n'
# 108dp canvas, mark 48dp (cell 3.2) centered -> inside 66dp safe circle (diag 67.9? use 45dp: cell 3)
cell=3; off=(108-45)/2
w('ic_launcher_foreground.xml',vec([(G,grid_rects(f,off,off,cell)),(BL,grid_rects(a,off,off,cell))],108,108,108,108))
w('ic_launcher_monochrome.xml',vec([('#FFFFFFFF',grid_rects(merged,off,off,cell))],108,108,108,108))
w('ic_launcher_background.xml',vec([(BG,'M0,0h108v108h-108z')],108,108,108,108))
w('ic_stat_omasend.xml',vec([('#FFFFFFFF',grid_rects(merged,1.5,1.5,1.4))],24,24,24,24))
w('omasend_mark.xml',vec([(G,grid_rects(f)),(BL,grid_rects(a))],300,300,48,48))
print(sorted(os.listdir(O)))
# Legacy launcher PNGs per density (Android uses the adaptive vectors on API 26+)
for dens,px in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
    os.makedirs(f'{O}/mipmap-{dens}',exist_ok=True)
    cairosvg.svg2png(bytestring=svg_mark(f,a,G,BL,BG,pad=90,rx=0,size=px).encode(),write_to=f'{O}/mipmap-{dens}/ic_launcher.png',output_width=px,output_height=px)
    cairosvg.svg2png(bytestring=svg_mark(f,a,G,BL,BG,pad=110,rx=240,size=px).encode(),write_to=f'{O}/mipmap-{dens}/ic_launcher_round.png',output_width=px,output_height=px)
