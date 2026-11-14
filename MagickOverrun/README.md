# MagickOverrun — ImageMagick `ShearRotateImage` heap out-of-bounds write

| | |
|---|---|
| **Product + version** | ImageMagick ≤ 7.1.2-35 (2026-10-31), all earlier; also `master` before `1360d45` |
| **CVSS** | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` → **7.8 HIGH** |
| **CWE** | CWE-787 (Out-of-bounds Write) |

**Fix commit:** [1360d45eeee6ce2e6f7a895911ffb7485c0c1a70](https://github.com/ImageMagick/ImageMagick/commit/1360d45eeee6ce2e6f7a895911ffb7485c0c1a70)
— *"Fixed possible out of bounds write in ShearRotateImage (GHSA-8xm2-q8hq-m68q)"*, ImageMagick maintainer Dirk Lemstra, 2026-11-13. Unreleased: the newest tag `7.1.2-35` predates it, so **every released ImageMagick is still vulnerable**.

## Root cause

`ShearRotateImage()` (the core of ImageMagick's `-rotate` / `-shear` for non-90° angles) rotates by three shears via `XShearImage()` / `YShearImage()`. In the `RIGHT` direction of `XShearImage()` (and `DOWN` of `YShearImage()`), pixels are transferred right-to-left with a per-row displacement `step`, and then the left gap is filled with the background colour:

```c
case RIGHT:                                   /* MagickCore/shear.c @ 1360d45~1 */
{
    p+=(ptrdiff_t) width*GetPixelChannels(image);
    q=p+step*(ssize_t) GetPixelChannels(image);
    for (i=0; i < (ssize_t) width; i++) {
        p-=(ptrdiff_t)GetPixelChannels(image);
        q-=GetPixelChannels(image);
        if ((size_t) (x_offset+(ssize_t) width+step-i) > image->columns)
            continue;                          /* only guards the in-loop write */
        GetPixelInfoPixel(image,p,&source);
        CompositePixelInfoAreaBlend(&pixel,(double) pixel.alpha,
            &source,(double) GetPixelAlpha(image,p),area,&destination);
        SetPixelViaPixelInfo(image,&destination,q);   /* in-loop write (guarded) */
        GetPixelInfoPixel(image,p,&pixel);
    }
    CompositePixelInfoAreaBlend(&pixel,(double) pixel.alpha,
        &background,(double) background.alpha,area,&destination);
    q-=GetPixelChannels(image);
    SetPixelViaPixelInfo(image,&destination,q);       /* UNGUARDED */
    for (i=0; i < (step-1); i++) {
        q-=GetPixelChannels(image);
        SetPixelViaPixelInfo(image,&background,q);    /* UNGUARDED  <-- CWE-787 */
    }
    break;
}
```

The trailing fill writes `step` pixels at columns `[x_offset, x_offset + step - 1]`. The in-loop `continue` only guards the *in-loop* write; the **trailing `destination`/`background` writes are not bounds-checked**. When `step > image->columns - x_offset`, those writes land at column ≥ `image->columns`, i.e. past the end of the row (and for the last row of the pixel cache, past the end of the whole allocation) — a heap out-of-bounds **write**.

The fix adds an up-front guard and drops the redundant in-loop guard:

```c
if (step > (ssize_t) image->columns-x_offset-(ssize_t) width)
    break;      /* skip this row: the destination region no longer fits */
```

The same commit also corrects `ShearRotateImage`'s `bounds.x` border computation (previously `(shear_width > bounds.width) ? width : ...`, which always chose the too-small `width`), which is what lets a real rotation leave the right-side padding too small and make `step > columns - x_offset - width` reachable from a normal `-rotate`/`-shear`.

## Exploit chain

1. Attacker supplies a crafted image and the victim/server rotates or shears it (`magick input -rotate 44 out.png`, or any library call to `ShearRotateImage`).
2. `ShearRotateImage` computes an under-sized border (`bounds.x`) and calls `XShearImage` with `(columns, x_offset, width)` such that `step > columns - x_offset - width` on the outer rows.
3. In `XShearImage`'s `RIGHT` branch the in-loop guard skips only the in-loop writes; the trailing `SetPixelViaPixelInfo(image,&background,q)` fill runs unconditionally and writes past the row → heap overflow.

## Exploitability assessment (honest)

**Preconditions / threat model.** Processing an untrusted image with a rotation/shear is routine and unauthenticated in every ImageMagick deployment (CLI, CMS upload pipelines, image-resize services). The trigger needs a shear angle large enough (e.g. close to ±45°) and image dimensions that make the buggy `bounds.x` border insufficient — the same commit's geometry fix confirms such configurations exist. This is a *local* (`AV:L`) file-processing boundary: the attacker must cause a crafted image to be rotated/sheared.

**What is demonstrated vs. claimed.** The PoC demonstrates the **memory-safety primitive** — the verbatim pre-fix loop writes 8 Quantums past the end of the pixel row and clobbers a canary; the fixed loop's guard blocks it. The `C:H/I:H/A:H` score is the industry-standard rating for CWE-787 in a memory-unsafe codebase (heap overflow ⇒ arbitrary write, crash, and — ImageMagick's long CVE history shows — code execution). The PoC demonstrates the write (I) and the memory corruption (A); **RCE/info-leak (C) is potential, not directly demonstrated**, and is stated as such.

## Self-critique (3 ways this might NOT work)

1. **"The extracted loop isn't the real code path."** — It is a byte-for-byte extraction of `XShearImage`'s `RIGHT` branch from `MagickCore/shear.c @ 1360d45~1`; only the MagickCore *helpers* (`GetPixelChannels`, `GetPixelInfoPixel`, `SetPixelViaPixelInfo`, `CompositePixelInfoAreaBlend`) are stubbed to their behaviour-equivalent minimal forms because `shear.c` cannot compile standalone. The pointer arithmetic, the guard, and the unguarded writes are identical. (Verified against the upstream blob and the fix diff.)
2. **"`step > columns - x_offset` is unreachable from a real rotate."** — The maintainer's fix *also* changes the `bounds.x` computation precisely because the old border could be too small; that is the reachability precondition. The PoC exercises the loop directly with the triggering geometry rather than re-deriving `bounds.x` from a specific pixel size, which is documented here and in `finding.json`.
3. **"It only corrupts the next row, not past the allocation."** — For interior rows the write lands in the next row of the *same* pixel-cache allocation (still memory corruption / wrong output). `YShearImage`'s `DOWN` branch writes through a contiguous `1×rows` column nexus buffer, and the extreme-corner geometry (`max step` on an edge row/column) writes past the buffer allocation — a genuine heap overflow. The PoC models the "write past the buffer" case directly (canary immediately after the row) because that is the memory-safety primitive being fixed; the fix's guard removes the write altogether.

## Run

```bash
bash run.sh
```

Expected output (abridged):

```
[vulnerable] XShearImage RIGHT (pre-fix 1360d45~1)
    canary[0] = 0x1111 (expected 0xbeef)
    reported OOB write: 8 Quantums past row end
    canary words clobbered: 8

[fixed    ] XShearImage RIGHT (commit 1360d45, guard added)
    reported OOB write: 0 Quantums past row end
    canary words clobbered: 0

MAGICKOVERRUN-OK: vulnerable path writes 8 Quantums past the row
  (canary clobbered = heap OOB write); fixed path's up-front guard
  skips the row and leaves the canary intact.
```

## Files

- `vendor/shear.c` — verbatim extraction of the vulnerable + fixed `XShearImage` `RIGHT` loop.
- `exploit.c` — driver (pixel row + canary guard, differential vulnerable/fixed).
- `run.sh` — builds with the zig toolchain and runs the differential (exit 0 on success).
- `finding.json` — machine-checkable evidence contract.
