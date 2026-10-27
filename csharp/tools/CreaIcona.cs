// Crea icona.ico con tutti i formati usati da Windows (Esplora risorse, desktop, barra delle
// applicazioni, Alt+Tab), ognuno disegnato alla sua misura per restare nitido.
// Uso: compilato insieme a src\*.cs con /main:ClubLogListener.CreaIcona, poi
//   crea_icona.exe <percorso\icona.ico>

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;

namespace ClubLogListener
{
    static class CreaIcona
    {
        static readonly int[] Sizes = { 16, 20, 24, 32, 40, 48, 64, 96, 128, 256 };

        // Immagine 32 bit in formato DIB (dal basso verso l'alto) più la maschera AND vuota
        static byte[] Dib(Bitmap bmp)
        {
            int s = bmp.Width;
            int maskRow = (s + 31) / 32 * 4;
            var ms = new MemoryStream();
            var w = new BinaryWriter(ms);
            w.Write(40);           // biSize
            w.Write(s);            // biWidth
            w.Write(s * 2);        // biHeight: immagine + maschera
            w.Write((short)1);     // biPlanes
            w.Write((short)32);    // biBitCount
            w.Write(0);            // biCompression = BI_RGB
            w.Write(s * s * 4 + maskRow * s);
            w.Write(0);
            w.Write(0);
            w.Write(0);
            w.Write(0);
            BitmapData data = bmp.LockBits(new Rectangle(0, 0, s, s), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            var row = new byte[s * 4];
            for (int y = s - 1; y >= 0; y--)
            {
                Marshal.Copy(data.Scan0 + y * data.Stride, row, 0, row.Length);
                w.Write(row);
            }
            bmp.UnlockBits(data);
            w.Write(new byte[maskRow * s]);
            return ms.ToArray();
        }

        static int Main(string[] args)
        {
            string path = Path.GetFullPath(args.Length > 0 ? args[0] : "icona.ico");
            var images = new List<byte[]>();
            foreach (int s in Sizes)
                using (Bitmap bmp = IconArt.Draw(s, IconArt.Green))
                {
                    if (s == 256)
                    {
                        // Il formato più grande in PNG, come fa Windows: file molto più piccolo
                        var png = new MemoryStream();
                        bmp.Save(png, ImageFormat.Png);
                        images.Add(png.ToArray());
                    }
                    else
                        images.Add(Dib(bmp));
                }
            using (var w = new BinaryWriter(File.Create(path)))
            {
                w.Write((short)0);
                w.Write((short)1);  // icona
                w.Write((short)Sizes.Length);
                int offset = 6 + 16 * Sizes.Length;
                for (int i = 0; i < Sizes.Length; i++)
                {
                    w.Write((byte)(Sizes[i] >= 256 ? 0 : Sizes[i]));
                    w.Write((byte)(Sizes[i] >= 256 ? 0 : Sizes[i]));
                    w.Write((byte)0);
                    w.Write((byte)0);
                    w.Write((short)1);
                    w.Write((short)32);
                    w.Write(images[i].Length);
                    w.Write(offset);
                    offset += images[i].Length;
                }
                foreach (byte[] img in images)
                    w.Write(img);
            }
            Console.WriteLine("Creato " + path);
            return 0;
        }
    }
}
