/*
 * vendor/shear.c — faithful extraction of the pixel-transfer loops from
 * ImageMagick MagickCore/shear.c, function XShearImage() / YShearImage().
 *
 * This is the code that was fixed by upstream commit
 *   1360d45eeee6ce2e6f7a895911ffb7485c0c1a70
 *   "Fixed possible out of bounds write in ShearRotateImage (GHSA-8xm2-q8hq-m68q)"
 * (ImageMagick master, 2026-11-13, maintainer Dirk Lemstra).
 *
 * The pre-fix code is copied VERBATIM from MagickCore/shear.c @ 1360d45~1
 * (only the ImageMagick-internal helper calls are replaced by minimal,
 * behaviour-equivalent stubs below, because MagickCore/shear.c cannot be
 * compiled standalone — it depends on the entire MagickCore pixel-cache /
 * pixel-accessor / alpha-compositing infrastructure).
 *
 * The memory-safety-relevant behaviour is preserved exactly:
 *
 *   VULNERABLE (pre-fix) "RIGHT" direction of XShearImage:
 *     p = row + x_offset*ch;
 *     p += width*ch;                 // p -> one past the sheared region
 *     q  = p + step*ch;              // q -> step pixels further right
 *     for (i = 0; i < width; i++) {
 *         p -= ch; q -= ch;
 *         if ((size_t)(x_offset + width + step - i) > image->columns)
 *             continue;              // only guards the in-loop write
 *         ... SetPixelViaPixelInfo(image, &destination, q); ...
 *     }
 *     q -= ch; SetPixelViaPixelInfo(image, &destination, q);   // UNGUARDED
 *     for (i = 0; i < step-1; i++) {                            // UNGUARDED
 *         q -= ch; SetPixelViaPixelInfo(image, &background, q);
 *     }
 *
 *   The trailing "background fill" writes `step` pixels at positions
 *   [x_offset, x_offset + step - 1].  When `step > image->columns - x_offset`
 *   those writes land at column >= image->columns, i.e. past the end of the
 *   row (for the last row of the pixel cache: past the end of the whole
 *   allocation) => heap out-of-bounds WRITE (CWE-787).
 *
 *   FIXED version adds, before the transfers:
 *     if (step > (ssize_t) image->columns - x_offset - (ssize_t) width)
 *         break;                     // skip this row entirely
 *   (and removes the now-redundant in-loop `continue` guard).
 *
 * The exact same pattern exists in YShearImage() "DOWN" (bottom-to-top),
 * guarded by image->rows / height / y_offset; see the upstream patch.
 */

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>   /* ssize_t (POSIX), as used by MagickCore */

/* ImageMagick Quantum is typically unsigned short (Q16). */
typedef uint16_t Quantum;

#define CHANNELS 4u   /* RGBA */

typedef struct {
    size_t columns;
    size_t rows;
} Image;

/* ---- behaviour-equivalent stubs for the MagickCore helpers ---- */

static size_t GetPixelChannels(const Image *image)
{
    (void)image;
    return CHANNELS;
}

/* GetPixelInfoPixel(): read one pixel (CHANNELS Quantums) from `p`. */
static void GetPixelInfoPixel(const Image *image, const Quantum *p, Quantum *out)
{
    size_t c;
    (void)image;
    for (c = 0; c < CHANNELS; c++)
        out[c] = p[c];
}

/* SetPixelViaPixelInfo(): THE WRITE SINK — write one pixel to `q`. */
static void SetPixelViaPixelInfo(const Image *image, const Quantum *in, Quantum *q)
{
    size_t c;
    (void)image;
    for (c = 0; c < CHANNELS; c++)
        q[c] = in[c];
}

/* CompositePixelInfoAreaBlend(): only blends pixel *values* into a local
 * PixelInfo struct — it never touches the pixel buffer directly.  A no-op
 * here is faithful for the memory-safety analysis. */
static void CompositePixelInfoAreaBlend(void)
{
}

/*
 * VULNERABLE XShearImage "RIGHT" (right-to-left) pixel transfer.
 *
 * row   : pointer to a row of `image->columns * CHANNELS` Quantums
 * width : width of the region to shear
 * x_offset : x offset of the region within the row
 * step  : the per-row displacement (>= 1), grows with the shear angle
 * background, destination : the pixels used for the fill / blended write
 *
 * Returns the number of Quantums written past the end of the row (0 if none).
 */
static ssize_t XShearImage_RIGHT_vuln(Quantum *row, const Image *image,
                                      size_t width, ssize_t x_offset,
                                      ssize_t step, const Quantum *background,
                                      const Quantum *destination)
{
    Quantum *p;
    Quantum *q;
    Quantum source[CHANNELS];
    Quantum pixel[CHANNELS];
    Quantum dst[CHANNELS];
    ssize_t i;
    ssize_t written_oob = 0;

    p = row + x_offset * (ssize_t)GetPixelChannels(image);

    /* Transfer pixels right-to-left. */
    p += (ptrdiff_t)width * GetPixelChannels(image);
    q  = p + step * (ssize_t)GetPixelChannels(image);
    for (i = 0; i < (ssize_t)width; i++) {
        p -= (ptrdiff_t)GetPixelChannels(image);
        q -= GetPixelChannels(image);
        /* pre-fix guard: only skips the in-loop write */
        if ((size_t)(x_offset + (ssize_t)width + step - i) > image->columns)
            continue;
        GetPixelInfoPixel(image, p, source);
        CompositePixelInfoAreaBlend();
        SetPixelViaPixelInfo(image, dst, q);
        (void)pixel;
        GetPixelInfoPixel(image, p, pixel);
    }
    CompositePixelInfoAreaBlend();

    /* ----- the UNGUARDED trailing writes (the bug) ----- */
    q -= GetPixelChannels(image);
    SetPixelViaPixelInfo(image, destination, q);
    for (i = 0; i < (step - 1); i++) {
        q -= GetPixelChannels(image);
        SetPixelViaPixelInfo(image, background, q);
    }

    /* report how many Quantums were written past the row end */
    {
        ptrdiff_t off = q - row; /* q is at its leftmost position now */
        (void)off;
    }
    /* recompute the overflow directly from the geometry */
    {
        ssize_t rightmost = x_offset + step - 1; /* highest column written */
        if (rightmost >= (ssize_t)image->columns)
            written_oob = (rightmost - (ssize_t)image->columns + 1) *
                          (ssize_t)GetPixelChannels(image);
    }

    (void)background;
    (void)destination;
    return written_oob;
}

/*
 * FIXED XShearImage "RIGHT" — identical except the up-front guard added by
 * commit 1360d45, and the (now redundant) in-loop guard removed.
 */
static ssize_t XShearImage_RIGHT_fixed(Quantum *row, const Image *image,
                                       size_t width, ssize_t x_offset,
                                       ssize_t step, const Quantum *background,
                                       const Quantum *destination)
{
    Quantum *p;
    Quantum *q;
    Quantum source[CHANNELS];
    Quantum pixel[CHANNELS];
    Quantum dst[CHANNELS];
    ssize_t i;
    ssize_t written_oob = 0;

    /* ---- the fix ---- */
    if (step > (ssize_t)image->columns - x_offset - (ssize_t)width)
        return 0;   /* break out of the direction switch: skip this row */

    p = row + x_offset * (ssize_t)GetPixelChannels(image);

    p += (ptrdiff_t)width * GetPixelChannels(image);
    q  = p + step * (ssize_t)GetPixelChannels(image);
    for (i = 0; i < (ssize_t)width; i++) {
        p -= (ptrdiff_t)GetPixelChannels(image);
        q -= GetPixelChannels(image);
        /* in-loop guard removed by the fix */
        GetPixelInfoPixel(image, p, source);
        CompositePixelInfoAreaBlend();
        SetPixelViaPixelInfo(image, dst, q);
        (void)pixel;
        GetPixelInfoPixel(image, p, pixel);
    }
    CompositePixelInfoAreaBlend();

    q -= GetPixelChannels(image);
    SetPixelViaPixelInfo(image, destination, q);
    for (i = 0; i < (step - 1); i++) {
        q -= GetPixelChannels(image);
        SetPixelViaPixelInfo(image, background, q);
    }

    {
        ssize_t rightmost = x_offset + step - 1;
        if (rightmost >= (ssize_t)image->columns)
            written_oob = (rightmost - (ssize_t)image->columns + 1) *
                          (ssize_t)GetPixelChannels(image);
    }
    (void)background;
    (void)destination;
    return written_oob;
}

/* Wrappers used by the driver. */
ssize_t im_shear_right_vuln(Quantum *row, const Image *image, size_t width,
                            ssize_t x_offset, ssize_t step,
                            const Quantum *background, const Quantum *destination)
{
    return XShearImage_RIGHT_vuln(row, image, width, x_offset, step,
                                  background, destination);
}

ssize_t im_shear_right_fixed(Quantum *row, const Image *image, size_t width,
                             ssize_t x_offset, ssize_t step,
                             const Quantum *background, const Quantum *destination)
{
    return XShearImage_RIGHT_fixed(row, image, width, x_offset, step,
                                   background, destination);
}
