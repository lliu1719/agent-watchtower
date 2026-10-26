import AppKit
// Light-background variant of the glowing wordmark on black: the silver letters become dark slate and opaque,
// coloured parts (the eye, the blue flare) keep their colour. Alpha comes from brightness, as for the dark variant,
// but saturates earlier so the letters are solid. Then crop to content.
let a = CommandLine.arguments
guard let img = NSImage(contentsOfFile: a[1]), let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else { print("cannot read"); exit(1) }
let w = cg.width, h = cg.height
var px = [UInt8](repeating: 0, count: w * h * 4)
let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: CGColorSpaceCreateDeviceRGB(),
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
let floor = 18.0, solid = Double(a.count > 3 ? Double(a[3])! : 110)   // brightness at which a letter pixel is fully opaque
let ink = (r: 28.0, g: 32.0, b: 48.0)                                 // dark slate for the letters
var ex0 = w, ey0 = h, ex1 = 0, ey1 = 0
for y in 0..<h { for x in 0..<w {
    let i = (y * w + x) * 4
    if px[i] > 235 && px[i+1] > 175 && px[i+2] < 150 && px[i+2] > 30 && abs(x - 960) < 220 { ex0 = min(ex0, x); ex1 = max(ex1, x); ey0 = min(ey0, y); ey1 = max(ey1, y) }
}}
let ecx = Double(ex0 + ex1) / 2, ecy = Double(ey0 + ey1) / 2, er = Double(max(ex1 - ex0, ey1 - ey0)) / 2 * (a.count > 4 ? Double(a[4])! : 0.8)
print("eye at \(Int(ecx)),\(Int(ecy)) r \(Int(er))")
var minX = w, minY = h, maxX = 0, maxY = 0
for y in 0..<h { for x in 0..<w {
    let i = (y * w + x) * 4
    let r = Double(px[i]), g = Double(px[i+1]), b = Double(px[i+2])
    let m = max(r, g, b), n = min(r, g, b)
    let sat = m > 0 ? (m - n) / m : 0
    var alpha: Double, cr: Double, cg2: Double, cb: Double
    let d = ((Double(x) - ecx) * (Double(x) - ecx) + (Double(y) - ecy) * (Double(y) - ecy)).squareRoot()
    if d < er * 0.97 {
        alpha = 255; cr = r; cg2 = g; cb = b
    } else if d < er * 1.03 {   // feather the ring's edge
        let t = (er * 1.03 - d) / (er * 0.06)
        alpha = max(t * 255, m <= floor ? 0 : min(255, (m - floor) / (255 - floor) * 255))
        let k = m > 0 ? 255 / m : 0
        cr = t * r + (1 - t) * min(255, r * k); cg2 = t * g + (1 - t) * min(255, g * k); cb = t * b + (1 - t) * min(255, b * k)
    } else if sat < 0.5 {   // neutral: the silver letters and their soft glow
        let t = max(0, min(1, (m - floor) / (solid - floor)))
        alpha = t * t * (3 - 2 * t) * 255
        // brighter silver -> darker ink, keeping a little of the metal's shading
        let shade = 0.75 + 0.5 * (1 - m / 255)
        cr = min(255, ink.r * shade); cg2 = min(255, ink.g * shade); cb = min(255, ink.b * shade)
    } else {          // coloured: keep the colour, alpha from brightness as in the dark variant
        alpha = m <= floor ? 0 : min(255, (m - floor) / (255 - floor) * 255)
        let k = m > 0 ? 255 / m : 0
        cr = min(255, r * k); cg2 = min(255, g * k); cb = min(255, b * k)
        // colour un-premultiplied to full brightness, so the eye stays vivid on white
    }
    let p = alpha / 255
    px[i] = UInt8(cr * p); px[i+1] = UInt8(cg2 * p); px[i+2] = UInt8(cb * p); px[i+3] = UInt8(alpha)
    if alpha > 24 { minX = min(minX, x); maxX = max(maxX, x); minY = min(minY, y); maxY = max(maxY, y) }
}}
let pad = 12
let crop = CGRect(x: max(0, minX - pad), y: max(0, minY - pad), width: min(w, maxX + pad) - max(0, minX - pad), height: min(h, maxY + pad) - max(0, minY - pad))
let out = ctx.makeImage()!.cropping(to: crop)!
try! NSBitmapImageRep(cgImage: out).representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: a[2]))
print("wrote \(a[2]) \(out.width)x\(out.height)")
