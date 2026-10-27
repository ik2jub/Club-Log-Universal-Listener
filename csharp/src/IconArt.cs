// Disegno dell'icona: cerchio colorato con la scritta CL. Usato per la tray (un colore per
// stato) e da tools\CreaIcona.cs per icona.ico (verde).

using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

namespace ClubLogListener
{
    static class IconArt
    {
        public static readonly Color Green = ColorTranslator.FromHtml("#1a7f37");

        public static Bitmap Draw(int size, Color color)
        {
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                g.Clear(Color.Transparent);
                float pen = Math.Max(1F, size / 16F);
                float inset = pen / 2 + size / 32F;
                var circle = new RectangleF(inset, inset, size - 2 * inset, size - 2 * inset);
                using (var b = new SolidBrush(color))
                    g.FillEllipse(b, circle);
                using (var p = new Pen(Color.White, pen))
                    g.DrawEllipse(p, circle);
                using (var path = new GraphicsPath())
                using (var family = new FontFamily("Segoe UI"))
                {
                    path.AddString("CL", family, (int)FontStyle.Bold, size * 0.44F, PointF.Empty, StringFormat.GenericTypographic);
                    RectangleF r = path.GetBounds();
                    using (var m = new Matrix())
                    {
                        m.Translate(size / 2F - r.X - r.Width / 2, size / 2F - r.Y - r.Height / 2);
                        path.Transform(m);
                    }
                    g.FillPath(Brushes.White, path);
                }
            }
            return bmp;
        }

        public static Icon MakeIcon(int size, Color color)
        {
            using (Bitmap bmp = Draw(size, color))
                return Icon.FromHandle(bmp.GetHicon());
        }
    }
}
