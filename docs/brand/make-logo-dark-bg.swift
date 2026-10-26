import AppKit
// Black -> transparent for glowing artwork on black: alpha = brightest channel, colour un-premultiplied; then crop to content.
let a = CommandLine.arguments
guard let img = NSImage(contentsOfFile: a[1]), let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else { print("cannot read"); exit(1) }
let w = cg.width, h = cg.height
var px = [UInt8](repeating: 0, count: w * h * 4)
let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: CGColorSpaceCreateDeviceRGB(),
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
let floor = 18.0   // the background is not quite black; anything this dark becomes fully transparent
var minX = w, minY = h, maxX = 0, maxY = 0
for y in 0..<h { for x in 0..<w {
    let i = (y * w + x) * 4
    let r = Double(px[i]), g = Double(px[i+1]), b = Double(px[i+2])
    let m = max(r, g, b)
    let alpha = m <= floor ? 0 : min(255, (m - floor) / (255 - floor) * 255)
    // keep premultiplied form: colour scaled by alpha/255 relative to its max
    let k = m > 0 ? alpha / m : 0
    px[i] = UInt8(min(255, r * k)); px[i+1] = UInt8(min(255, g * k)); px[i+2] = UInt8(min(255, b * k)); px[i+3] = UInt8(alpha)
    if alpha > 24 { minX = min(minX, x); maxX = max(maxX, x); minY = min(minY, y); maxY = max(maxY, y) }
}}
let pad = 12
let crop = CGRect(x: max(0, minX - pad), y: max(0, minY - pad), width: min(w, maxX + pad) - max(0, minX - pad), height: min(h, maxY + pad) - max(0, minY - pad))
let out = ctx.makeImage()!.cropping(to: crop)!
let rep = NSBitmapImageRep(cgImage: out)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: a[2]))
print("wrote \(a[2]) \(out.width)x\(out.height)")
